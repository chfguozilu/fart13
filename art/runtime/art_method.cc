/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "art_method.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <queue>
#include <string>
#include <utility>
#include <unordered_set>
#include <vector>

#include <pthread.h>
#include <unistd.h>

#include "android-base/stringprintf.h"

#include "arch/context.h"
#include "art_method-inl.h"
#include "base/enums.h"
#include "base/stl_util.h"
#include "class_linker-inl.h"
#include "class_root-inl.h"
#include "debugger.h"
#include "dex/class_accessor-inl.h"
#include "dex/descriptors_names.h"
#include "dex/dex_file-inl.h"
#include "dex/dex_file_exception_helpers.h"
#include "dex/dex_instruction.h"
#include "dex/signature-inl.h"
#include "entrypoints/runtime_asm_entrypoints.h"
#include "runtime_snapshot/runtime_snapshot.h"
#include "gc/accounting/card_table-inl.h"
#include "hidden_api.h"
#include "interpreter/interpreter.h"
#include "jit/jit.h"
#include "jit/jit_code_cache.h"
#include "jit/profiling_info.h"
#include "jni/jni_internal.h"
#include "mirror/class-inl.h"
#include "mirror/class_ext-inl.h"
#include "mirror/executable.h"
#include "mirror/object-inl.h"
#include "mirror/object_array-inl.h"
#include "mirror/string.h"
#include "oat_file-inl.h"
#include "quicken_info.h"
#include "runtime_callbacks.h"
#include "scoped_thread_state_change-inl.h"
#include "vdex_file.h"

namespace art {

    using android::base::StringPrintf;

    extern "C" void art_quick_invoke_stub(ArtMethod*, uint32_t*, uint32_t, Thread*, JValue*,
        const char*);
    extern "C" void art_quick_invoke_static_stub(ArtMethod*, uint32_t*, uint32_t, Thread*, JValue*,
        const char*);

    extern "C" __attribute__((visibility("hidden"))) uint32_t artRuntimeProfileActive;

    namespace runtime_snapshot {
        namespace {

            constexpr uint32_t kSnapshotFileVersion = 2u;
            constexpr uint32_t kSnapshotRecordMagic = 0x31525052u;  // "RPR1" in little endian.
            constexpr uint32_t kMaximumCodeItemSize = 1024u * 1024u;
            constexpr uint32_t kFixedRecordSize = 96u;
            constexpr uint32_t kFileHeaderSize = 16u;
            constexpr uint32_t kFileFooterSize = 32u;

            struct DumpRecord final {
                CaptureStage stage;
                bool has_original_code_off;
                bool code_item_in_dex;
                bool is_compact_dex;
                uint32_t dex_method_idx;
                uint32_t original_code_off;
                uint32_t code_item_size;
                uint32_t dex_header_checksum;
                uint32_t dex_location_checksum;
                uint64_t dex_file_size;
                uint64_t dex_begin;
                uint64_t data_begin;
                uint64_t data_size;
                uint64_t runtime_code_item;
                std::array<uint8_t, DexFile::kSha1DigestSize> dex_signature;
                std::string dex_location;
                std::vector<uint8_t> code_item_bytes;
            };

            thread_local ArtMethod* g_probe_target = nullptr;

            pthread_mutex_t g_writer_mutex = PTHREAD_MUTEX_INITIALIZER;
            pthread_cond_t g_writer_cond = PTHREAD_COND_INITIALIZER;
            pthread_t g_writer_thread;
            bool g_writer_started = false;
            bool g_writer_stopping = false;
            bool g_writer_output_ok = false;
            int g_writer_fd = -1;
            std::queue<std::unique_ptr<DumpRecord>> g_record_queue;
            std::unordered_set<const DexFile*> g_dumped_dex_files;

            bool WriteFully(int fd, const void* buffer, size_t byte_count) {
                const uint8_t* cursor = reinterpret_cast<const uint8_t*>(buffer);
                while (byte_count != 0u) {
                    const ssize_t written = write(fd, cursor, byte_count);
                    if (written < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        return false;
                    }
                    if (written == 0) {
                        return false;
                    }
                    cursor += written;
                    byte_count -= static_cast<size_t>(written);
                }
                return true;
            }

            template <typename T>
            bool WriteValue(int fd, const T& value) {
                return WriteFully(fd, &value, sizeof(value));
            }

            bool WriteFileHeader(int fd) {
                constexpr uint8_t kMagic[8] = {'R', 'T', 'P', 'R', '1', '3', 0, 0};
                constexpr uint32_t kEndianTag = 0x12345678u;
                return WriteFully(fd, kMagic, sizeof(kMagic)) &&
                    WriteValue(fd, kSnapshotFileVersion) &&
                    WriteValue(fd, kEndianTag);
            }

            bool AppendHeaderBytes(std::array<uint8_t, kFixedRecordSize>* header,
                size_t* offset,
                const void* source,
                size_t byte_count) {
                if (*offset > header->size() || byte_count > header->size() - *offset) {
                    return false;
                }
                std::memcpy(header->data() + *offset, source, byte_count);
                *offset += byte_count;
                return true;
            }

            bool WriteRecord(int fd, const DumpRecord& record, uint32_t* bytes_written) {
                if (record.code_item_bytes.size() != record.code_item_size ||
                    record.dex_location.size() > UINT32_MAX) {
                    errno = EINVAL;
                    return false;
                }
                const uint64_t total_size =
                    static_cast<uint64_t>(kFixedRecordSize) + record.dex_location.size() +
                        record.code_item_bytes.size();
                if (total_size > UINT32_MAX) {
                    errno = EFBIG;
                    return false;
                }

                const uint32_t record_size = static_cast<uint32_t>(total_size);
                const uint8_t stage = static_cast<uint8_t>(record.stage);
                const uint8_t flags =
                    (record.has_original_code_off ? 1u : 0u) |
                        (record.code_item_in_dex ? 2u : 0u) |
                        (record.is_compact_dex ? 4u : 0u);
                constexpr uint16_t kReserved = 0u;
                const uint32_t location_size = static_cast<uint32_t>(record.dex_location.size());

                // Serialize the fixed header first. The old implementation issued one
                // write() for every scalar field, which both multiplied syscall count and
                // allowed a failed record to end in the middle of its 96-byte header.
                std::array<uint8_t, kFixedRecordSize> header{};
                size_t offset = 0u;
                const bool header_ok =
                    AppendHeaderBytes(&header, &offset, &kSnapshotRecordMagic, sizeof(kSnapshotRecordMagic)) &&
                        AppendHeaderBytes(&header, &offset, &record_size, sizeof(record_size)) &&
                        AppendHeaderBytes(&header, &offset, &stage, sizeof(stage)) &&
                        AppendHeaderBytes(&header, &offset, &flags, sizeof(flags)) &&
                        AppendHeaderBytes(&header, &offset, &kReserved, sizeof(kReserved)) &&
                        AppendHeaderBytes(&header, &offset, &record.dex_method_idx,
                            sizeof(record.dex_method_idx)) &&
                        AppendHeaderBytes(&header, &offset, &record.original_code_off,
                            sizeof(record.original_code_off)) &&
                        AppendHeaderBytes(&header, &offset, &record.code_item_size,
                            sizeof(record.code_item_size)) &&
                        AppendHeaderBytes(&header, &offset, &record.dex_header_checksum,
                            sizeof(record.dex_header_checksum)) &&
                        AppendHeaderBytes(&header, &offset, &record.dex_location_checksum,
                            sizeof(record.dex_location_checksum)) &&
                        AppendHeaderBytes(&header, &offset, &record.dex_file_size,
                            sizeof(record.dex_file_size)) &&
                        AppendHeaderBytes(&header, &offset, &record.dex_begin, sizeof(record.dex_begin)) &&
                        AppendHeaderBytes(&header, &offset, &record.data_begin, sizeof(record.data_begin)) &&
                        AppendHeaderBytes(&header, &offset, &record.data_size, sizeof(record.data_size)) &&
                        AppendHeaderBytes(&header, &offset, &record.runtime_code_item,
                            sizeof(record.runtime_code_item)) &&
                        AppendHeaderBytes(&header, &offset, &location_size, sizeof(location_size)) &&
                        AppendHeaderBytes(&header, &offset, record.dex_signature.data(),
                            record.dex_signature.size());
                if (!header_ok || offset != header.size()) {
                    errno = EINVAL;
                    return false;
                }

                if (!WriteFully(fd, header.data(), header.size()) ||
                    !WriteFully(fd, record.dex_location.data(), record.dex_location.size()) ||
                    !WriteFully(fd, record.code_item_bytes.data(), record.code_item_bytes.size())) {
                    return false;
                }
                *bytes_written = record_size;
                return true;
            }

            bool WriteFileFooter(int fd, uint64_t record_count, uint64_t record_bytes) {
                constexpr uint8_t kFooterMagic[8] = {'R', 'P', 'R', 'D', 'O', 'N', 'E', 0};
                const uint64_t final_file_size =
                    static_cast<uint64_t>(kFileHeaderSize) + record_bytes + kFileFooterSize;
                return WriteFully(fd, kFooterMagic, sizeof(kFooterMagic)) &&
                    WriteValue(fd, record_count) &&
                    WriteValue(fd, record_bytes) &&
                    WriteValue(fd, final_file_size);
            }

            void* WriterMain(void*) {
                bool output_ok = WriteFileHeader(g_writer_fd);
                uint64_t record_count = 0u;
                uint64_t record_bytes = 0u;

                for (;;) {
                    std::unique_ptr<DumpRecord> record;
                    pthread_mutex_lock(&g_writer_mutex);
                    while (g_record_queue.empty() && !g_writer_stopping) {
                        pthread_cond_wait(&g_writer_cond, &g_writer_mutex);
                    }
                    if (g_record_queue.empty() && g_writer_stopping) {
                        pthread_mutex_unlock(&g_writer_mutex);
                        break;
                    }
                    record = std::move(g_record_queue.front());
                    g_record_queue.pop();
                    pthread_mutex_unlock(&g_writer_mutex);

                    if (output_ok) {
                        uint32_t bytes_written = 0u;
                        if (!WriteRecord(g_writer_fd, *record, &bytes_written)) {
                            output_ok = false;
                            PLOG(ERROR) << "[RuntimeProfile] writer failed";
                        } else {
                            ++record_count;
                            record_bytes += bytes_written;
                        }
                    }
                }

                if (g_writer_fd >= 0) {
                    if (output_ok && !WriteFileFooter(g_writer_fd, record_count, record_bytes)) {
                        output_ok = false;
                        PLOG(ERROR) << "[RuntimeProfile] footer write failed";
                    }
                    if (output_ok && fsync(g_writer_fd) != 0) {
                        output_ok = false;
                        PLOG(ERROR) << "[RuntimeProfile] fsync failed";
                    }
                    if (close(g_writer_fd) != 0) {
                        output_ok = false;
                        PLOG(ERROR) << "[RuntimeProfile] close failed";
                    }
                }
                pthread_mutex_lock(&g_writer_mutex);
                g_writer_output_ok = output_ok;
                pthread_mutex_unlock(&g_writer_mutex);
                return nullptr;
            }

            bool Enqueue(std::unique_ptr<DumpRecord> record) {
                pthread_mutex_lock(&g_writer_mutex);
                if (!g_writer_started || g_writer_stopping) {
                    pthread_mutex_unlock(&g_writer_mutex);
                    return false;
                }
                g_record_queue.push(std::move(record));
                pthread_cond_signal(&g_writer_cond);
                pthread_mutex_unlock(&g_writer_mutex);
                return true;
            }

            bool MarkDexFileForImage(const DexFile* dex_file) {
                pthread_mutex_lock(&g_writer_mutex);
                if (!g_writer_started || g_writer_stopping) {
                    pthread_mutex_unlock(&g_writer_mutex);
                    return false;
                }
                const bool first = g_dumped_dex_files.insert(dex_file).second;
                pthread_mutex_unlock(&g_writer_mutex);
                return first;
            }

            bool RangeContains(uintptr_t base,
                uintptr_t size,
                uintptr_t address,
                uintptr_t byte_count) {
                return address >= base &&
                    address - base < size &&
                    byte_count <= size - (address - base);
            }

        }  // namespace

        ArtMethod* GetProbeTarget() {
            return g_probe_target;
        }

        void SetProbeTarget(ArtMethod* method) {
            if (g_probe_target == nullptr && method != nullptr) {
                __atomic_add_fetch(&artRuntimeProfileActive, 1u, __ATOMIC_RELEASE);
            } else if (g_probe_target != nullptr && method == nullptr) {
                __atomic_sub_fetch(&artRuntimeProfileActive, 1u, __ATOMIC_RELEASE);
            }
            g_probe_target = method;
        }

        bool StartWriter(int fd) {
            if (fd < 0) {
                return false;
            }

            const int owned_fd = dup(fd);
            if (owned_fd < 0) {
                PLOG(ERROR) << "[RuntimeProfile] dup output fd failed";
                return false;
            }

            pthread_mutex_lock(&g_writer_mutex);
            if (g_writer_started) {
                pthread_mutex_unlock(&g_writer_mutex);
                close(owned_fd);
                LOG(ERROR) << "[RuntimeProfile] writer is already running";
                return false;
            }

            g_writer_fd = owned_fd;
            g_writer_stopping = false;
            g_writer_output_ok = false;
            g_dumped_dex_files.clear();
            const int create_result = pthread_create(&g_writer_thread, nullptr, WriterMain, nullptr);
            if (create_result != 0) {
                g_writer_fd = -1;
                pthread_mutex_unlock(&g_writer_mutex);
                close(owned_fd);
                LOG(ERROR) << "[RuntimeProfile] pthread_create failed: " << strerror(create_result);
                return false;
            }
            g_writer_started = true;
            pthread_mutex_unlock(&g_writer_mutex);
            return true;
        }

        bool StopWriter() {
            pthread_mutex_lock(&g_writer_mutex);
            if (!g_writer_started) {
                pthread_mutex_unlock(&g_writer_mutex);
                return false;
            }
            g_writer_stopping = true;
            pthread_cond_signal(&g_writer_cond);
            const pthread_t writer = g_writer_thread;
            pthread_mutex_unlock(&g_writer_mutex);

            const int join_result = pthread_join(writer, nullptr);
            if (join_result != 0) {
                LOG(ERROR) << "[RuntimeProfile] pthread_join failed: " << strerror(join_result);
                return false;
            }

            pthread_mutex_lock(&g_writer_mutex);
            const bool output_ok = g_writer_output_ok;
            g_writer_fd = -1;
            g_writer_started = false;
            g_writer_stopping = false;
            g_writer_output_ok = false;
            pthread_mutex_unlock(&g_writer_mutex);
            return output_ok;
        }

        bool IsWriterStarted() {
            pthread_mutex_lock(&g_writer_mutex);
            const bool started = g_writer_started && !g_writer_stopping;
            pthread_mutex_unlock(&g_writer_mutex);
            return started;
        }

        bool CaptureMethod(ArtMethod* method, CaptureStage stage) {
            if (!IsWriterStarted()) {
                return false;
            }
            if (method == nullptr || method->IsRuntimeMethod() || method->IsProxyMethod() ||
                method->IsNative() || method->IsAbstract() || !method->HasCodeItem()) {
                return false;
            }

            const DexFile* dex_file = method->GetDexFile();
            const dex::CodeItem* code_item = method->GetCodeItem();
            if (dex_file == nullptr || code_item == nullptr) {
                return false;
            }

            // Save the still-incomplete base Dex exactly once. Later records remain
            // method-granular patches keyed by dex identity + dex_method_idx.
            if (MarkDexFileForImage(dex_file) && dex_file->Begin() != nullptr &&
                dex_file->Size() != 0u && dex_file->Size() <= UINT32_MAX) {
                std::unique_ptr<DumpRecord> dex_record(new DumpRecord());
                dex_record->stage = CaptureStage::kDexImage;
                dex_record->has_original_code_off = false;
                dex_record->code_item_in_dex = true;
                dex_record->is_compact_dex = dex_file->IsCompactDexFile();
                dex_record->dex_method_idx = DexFile::kDexNoIndex32;
                dex_record->original_code_off = 0u;
                dex_record->code_item_size = static_cast<uint32_t>(dex_file->Size());
                dex_record->dex_header_checksum = dex_file->GetHeader().checksum_;
                dex_record->dex_location_checksum = dex_file->GetLocationChecksum();
                dex_record->dex_file_size = dex_file->Size();
                dex_record->dex_begin = reinterpret_cast<uintptr_t>(dex_file->Begin());
                dex_record->data_begin = reinterpret_cast<uintptr_t>(dex_file->DataBegin());
                dex_record->data_size = dex_file->DataSize();
                dex_record->runtime_code_item = 0u;
                std::copy_n(dex_file->GetHeader().signature_,
                    dex_record->dex_signature.size(),
                    dex_record->dex_signature.begin());
                dex_record->dex_location = dex_file->GetLocation();
                dex_record->code_item_bytes.assign(dex_file->Begin(),
                    dex_file->Begin() + dex_file->Size());
                Enqueue(std::move(dex_record));
            }

            const uint32_t code_item_size = dex_file->GetCodeItemSize(*code_item);
            if (code_item_size == 0u || code_item_size > kMaximumCodeItemSize) {
                LOG(WARNING) << "[RuntimeProfile] invalid CodeItem size=" << code_item_size
                             << " for " << method->PrettyMethod();
                return false;
            }

            std::unique_ptr<DumpRecord> record(new DumpRecord());
            record->stage = stage;
            record->has_original_code_off = false;
            record->original_code_off = 0u;
            record->dex_method_idx = method->GetDexMethodIndex();
            record->code_item_size = code_item_size;
            record->dex_file_size = dex_file->Size();
            record->dex_begin = reinterpret_cast<uintptr_t>(dex_file->Begin());
            record->data_begin = reinterpret_cast<uintptr_t>(dex_file->DataBegin());
            record->data_size = dex_file->DataSize();
            record->runtime_code_item = reinterpret_cast<uintptr_t>(code_item);
            record->is_compact_dex = dex_file->IsCompactDexFile();
            record->dex_header_checksum = dex_file->GetHeader().checksum_;
            record->dex_location_checksum = dex_file->GetLocationChecksum();
            std::copy_n(dex_file->GetHeader().signature_,
                record->dex_signature.size(),
                record->dex_signature.begin());
            record->dex_location = dex_file->GetLocation();

            const uintptr_t runtime_code_item = static_cast<uintptr_t>(record->runtime_code_item);
            record->code_item_in_dex =
                RangeContains(static_cast<uintptr_t>(record->dex_begin),
                    static_cast<uintptr_t>(record->dex_file_size),
                    runtime_code_item,
                    code_item_size) ||
                    RangeContains(static_cast<uintptr_t>(record->data_begin),
                        static_cast<uintptr_t>(record->data_size),
                        runtime_code_item,
                        code_item_size);

            ObjPtr<mirror::Class> declaring_class = method->GetDeclaringClass();
            const uint16_t class_def_index = declaring_class->GetDexClassDefIndex();
            if (class_def_index != DexFile::kDexNoIndex16) {
                const dex::ClassDef& class_def = dex_file->GetClassDef(class_def_index);
                const std::optional<uint32_t> code_off =
                    dex_file->GetCodeItemOffset(class_def, record->dex_method_idx);
                if (code_off.has_value()) {
                    record->has_original_code_off = true;
                    record->original_code_off = *code_off;
                }
            }

            // This copy must happen on the capture thread. A shell can reuse or free an
            // external CodeItem immediately after the probe returns.
            const uint8_t* code_bytes = reinterpret_cast<const uint8_t*>(code_item);
            record->code_item_bytes.assign(code_bytes, code_bytes + code_item_size);

            return Enqueue(std::move(record));
        }

    }  // namespace runtime_snapshot

// These two C-linkage symbols are referenced by the generated arm/arm64 Nterp
// assembly. Hidden visibility keeps them out of libart.so's exported dynamic
// symbol surface while still allowing local link-time relocation.
    extern "C" {

    __attribute__((visibility("hidden")))
    uint32_t artRuntimeProfileActive = 0u;

    __attribute__((visibility("hidden")))
    uint32_t artRuntimeProfileNterpGate(ArtMethod* method)
    REQUIRES_SHARED(Locks::mutator_lock_) {
        if (runtime_snapshot::GetProbeTarget() != method) {
            return 0u;
        }
        // Intercept even if capture fails: the active-probe contract is that target
        // bytecode must not execute. Failure is represented by the absence of a
        // stage-3 record, not by falling through into the target method.
        runtime_snapshot::CaptureMethod(method, runtime_snapshot::CaptureStage::kNterpEntry);
        return 1u;
    }

    }  // extern "C"

// Enforce that we have the right index for runtime methods.
    static_assert(ArtMethod::kRuntimeMethodDexMethodIndex == dex::kDexNoIndex,
        "Wrong runtime-method dex method index");

    ArtMethod* ArtMethod::GetCanonicalMethod(PointerSize pointer_size) {
        if (LIKELY(!IsCopied())) {
            return this;
        } else {
            ObjPtr<mirror::Class> declaring_class = GetDeclaringClass();
            DCHECK(declaring_class->IsInterface());
            ArtMethod* ret = declaring_class->FindInterfaceMethod(GetDexCache(),
                GetDexMethodIndex(),
                pointer_size);
            DCHECK(ret != nullptr);
            return ret;
        }
    }

    ArtMethod* ArtMethod::GetNonObsoleteMethod() {
        if (LIKELY(!IsObsolete())) {
            return this;
        }
        DCHECK_EQ(kRuntimePointerSize, Runtime::Current()->GetClassLinker()->GetImagePointerSize());
        if (IsDirect()) {
            return &GetDeclaringClass()->GetDirectMethodsSlice(kRuntimePointerSize)[GetMethodIndex()];
        } else {
            return GetDeclaringClass()->GetVTableEntry(GetMethodIndex(), kRuntimePointerSize);
        }
    }

    ArtMethod* ArtMethod::GetSingleImplementation(PointerSize pointer_size) {
        if (IsInvokable()) {
            // An invokable method single implementation is itself.
            return this;
        }
        DCHECK(!IsDefaultConflicting());
        ArtMethod* m = reinterpret_cast<ArtMethod*>(GetDataPtrSize(pointer_size));
        CHECK(m == nullptr || !m->IsDefaultConflicting());
        return m;
    }

    ArtMethod* ArtMethod::FromReflectedMethod(const ScopedObjectAccessAlreadyRunnable& soa,
        jobject jlr_method) {
        ObjPtr<mirror::Executable> executable = soa.Decode<mirror::Executable>(jlr_method);
        DCHECK(executable != nullptr);
        return executable->GetArtMethod();
    }

    ObjPtr<mirror::DexCache> ArtMethod::GetObsoleteDexCache() {
        PointerSize pointer_size = kRuntimePointerSize;
        DCHECK(!Runtime::Current()->IsAotCompiler()) << PrettyMethod();
        DCHECK(IsObsolete());
        ObjPtr<mirror::ClassExt> ext(GetDeclaringClass()->GetExtData());
        ObjPtr<mirror::PointerArray> obsolete_methods(ext.IsNull() ? nullptr : ext->GetObsoleteMethods());
        int32_t len = (obsolete_methods.IsNull() ? 0 : obsolete_methods->GetLength());
        DCHECK(len == 0 || len == ext->GetObsoleteDexCaches()->GetLength())
            << "len=" << len << " ext->GetObsoleteDexCaches()=" << ext->GetObsoleteDexCaches();
        // Using kRuntimePointerSize (instead of using the image's pointer size) is fine since images
        // should never have obsolete methods in them so they should always be the same.
        DCHECK_EQ(pointer_size, Runtime::Current()->GetClassLinker()->GetImagePointerSize());
        for (int32_t i = 0; i < len; i++) {
            if (this == obsolete_methods->GetElementPtrSize<ArtMethod*>(i, pointer_size)) {
                return ext->GetObsoleteDexCaches()->Get(i);
            }
        }
        CHECK(GetDeclaringClass()->IsObsoleteObject())
            << "This non-structurally obsolete method does not appear in the obsolete map of its class: "
            << GetDeclaringClass()->PrettyClass() << " Searched " << len << " caches.";
        CHECK_EQ(this,
            std::clamp(this,
                &(*GetDeclaringClass()->GetMethods(pointer_size).begin()),
                &(*GetDeclaringClass()->GetMethods(pointer_size).end())))
            << "class is marked as structurally obsolete method but not found in normal obsolete-map "
            << "despite not being the original method pointer for " << GetDeclaringClass()->PrettyClass();
        return GetDeclaringClass()->GetDexCache();
    }

    uint16_t ArtMethod::FindObsoleteDexClassDefIndex() {
        DCHECK(!Runtime::Current()->IsAotCompiler()) << PrettyMethod();
        DCHECK(IsObsolete());
        const DexFile* dex_file = GetDexFile();
        const dex::TypeIndex declaring_class_type = dex_file->GetMethodId(GetDexMethodIndex()).class_idx_;
        const dex::ClassDef* class_def = dex_file->FindClassDef(declaring_class_type);
        CHECK(class_def != nullptr);
        return dex_file->GetIndexForClassDef(*class_def);
    }

    void ArtMethod::ThrowInvocationTimeError() {
        DCHECK(!IsInvokable());
        if (IsDefaultConflicting()) {
            ThrowIncompatibleClassChangeErrorForMethodConflict(this);
        } else {
            DCHECK(IsAbstract());
            ThrowAbstractMethodError(this);
        }
    }

    InvokeType ArtMethod::GetInvokeType() {
        // TODO: kSuper?
        if (IsStatic()) {
            return kStatic;
        } else if (GetDeclaringClass()->IsInterface()) {
            return kInterface;
        } else if (IsDirect()) {
            return kDirect;
        } else if (IsSignaturePolymorphic()) {
            return kPolymorphic;
        } else {
            return kVirtual;
        }
    }

    size_t ArtMethod::NumArgRegisters(const char* shorty) {
        CHECK_NE(shorty[0], '\0');
        uint32_t num_registers = 0;
        for (const char* s = shorty + 1; *s != '\0'; ++s) {
            if (*s == 'D' || *s == 'J') {
                num_registers += 2;
            } else {
                num_registers += 1;
            }
        }
        return num_registers;
    }

    bool ArtMethod::HasSameNameAndSignature(ArtMethod* other) {
        ScopedAssertNoThreadSuspension ants("HasSameNameAndSignature");
        const DexFile* dex_file = GetDexFile();
        const dex::MethodId& mid = dex_file->GetMethodId(GetDexMethodIndex());
        if (GetDexCache() == other->GetDexCache()) {
            const dex::MethodId& mid2 = dex_file->GetMethodId(other->GetDexMethodIndex());
            return mid.name_idx_ == mid2.name_idx_ && mid.proto_idx_ == mid2.proto_idx_;
        }
        const DexFile* dex_file2 = other->GetDexFile();
        const dex::MethodId& mid2 = dex_file2->GetMethodId(other->GetDexMethodIndex());
        if (!DexFile::StringEquals(dex_file, mid.name_idx_, dex_file2, mid2.name_idx_)) {
            return false;  // Name mismatch.
        }
        return dex_file->GetMethodSignature(mid) == dex_file2->GetMethodSignature(mid2);
    }

    ArtMethod* ArtMethod::FindOverriddenMethod(PointerSize pointer_size) {
        if (IsStatic()) {
            return nullptr;
        }
        ObjPtr<mirror::Class> declaring_class = GetDeclaringClass();
        ObjPtr<mirror::Class> super_class = declaring_class->GetSuperClass();
        uint16_t method_index = GetMethodIndex();
        ArtMethod* result = nullptr;
        // Did this method override a super class method? If so load the result from the super class'
        // vtable
        if (super_class->HasVTable() && method_index < super_class->GetVTableLength()) {
            result = super_class->GetVTableEntry(method_index, pointer_size);
        } else {
            // Method didn't override superclass method so search interfaces
            if (IsProxyMethod()) {
                result = GetInterfaceMethodIfProxy(pointer_size);
                DCHECK(result != nullptr);
            } else {
                ObjPtr<mirror::IfTable> iftable = GetDeclaringClass()->GetIfTable();
                for (size_t i = 0; i < iftable->Count() && result == nullptr; i++) {
                    ObjPtr<mirror::Class> interface = iftable->GetInterface(i);
                    for (ArtMethod& interface_method : interface->GetVirtualMethods(pointer_size)) {
                        if (HasSameNameAndSignature(interface_method.GetInterfaceMethodIfProxy(pointer_size))) {
                            result = &interface_method;
                            break;
                        }
                    }
                }
            }
        }
        DCHECK(result == nullptr ||
            GetInterfaceMethodIfProxy(pointer_size)->HasSameNameAndSignature(
                result->GetInterfaceMethodIfProxy(pointer_size)));
        return result;
    }

    uint32_t ArtMethod::FindDexMethodIndexInOtherDexFile(const DexFile& other_dexfile,
        uint32_t name_and_signature_idx) {
        const DexFile* dexfile = GetDexFile();
        const uint32_t dex_method_idx = GetDexMethodIndex();
        const dex::MethodId& mid = dexfile->GetMethodId(dex_method_idx);
        const dex::MethodId& name_and_sig_mid = other_dexfile.GetMethodId(name_and_signature_idx);
        DCHECK_STREQ(dexfile->GetMethodName(mid), other_dexfile.GetMethodName(name_and_sig_mid));
        DCHECK_EQ(dexfile->GetMethodSignature(mid), other_dexfile.GetMethodSignature(name_and_sig_mid));
        if (dexfile == &other_dexfile) {
            return dex_method_idx;
        }
        const char* mid_declaring_class_descriptor = dexfile->StringByTypeIdx(mid.class_idx_);
        const dex::TypeId* other_type_id = other_dexfile.FindTypeId(mid_declaring_class_descriptor);
        if (other_type_id != nullptr) {
            const dex::MethodId* other_mid = other_dexfile.FindMethodId(
                *other_type_id, other_dexfile.GetStringId(name_and_sig_mid.name_idx_),
                other_dexfile.GetProtoId(name_and_sig_mid.proto_idx_));
            if (other_mid != nullptr) {
                return other_dexfile.GetIndexForMethodId(*other_mid);
            }
        }
        return dex::kDexNoIndex;
    }

    uint32_t ArtMethod::FindCatchBlock(Handle<mirror::Class> exception_type,
        uint32_t dex_pc, bool* has_no_move_exception) {
        // Set aside the exception while we resolve its type.
        Thread* self = Thread::Current();
        StackHandleScope<1> hs(self);
        Handle<mirror::Throwable> exception(hs.NewHandle(self->GetException()));
        self->ClearException();
        // Default to handler not found.
        uint32_t found_dex_pc = dex::kDexNoIndex;
        // Iterate over the catch handlers associated with dex_pc.
        CodeItemDataAccessor accessor(DexInstructionData());
        for (CatchHandlerIterator it(accessor, dex_pc); it.HasNext(); it.Next()) {
            dex::TypeIndex iter_type_idx = it.GetHandlerTypeIndex();
            // Catch all case
            if (!iter_type_idx.IsValid()) {
                found_dex_pc = it.GetHandlerAddress();
                break;
            }
            // Does this catch exception type apply?
            ObjPtr<mirror::Class> iter_exception_type = ResolveClassFromTypeIndex(iter_type_idx);
            if (UNLIKELY(iter_exception_type == nullptr)) {
                // Now have a NoClassDefFoundError as exception. Ignore in case the exception class was
                // removed by a pro-guard like tool.
                // Note: this is not RI behavior. RI would have failed when loading the class.
                self->ClearException();
                // Delete any long jump context as this routine is called during a stack walk which will
                // release its in use context at the end.
                delete self->GetLongJumpContext();
                LOG(WARNING) << "Unresolved exception class when finding catch block: "
                             << DescriptorToDot(GetTypeDescriptorFromTypeIdx(iter_type_idx));
            } else if (iter_exception_type->IsAssignableFrom(exception_type.Get())) {
                found_dex_pc = it.GetHandlerAddress();
                break;
            }
        }
        if (found_dex_pc != dex::kDexNoIndex) {
            const Instruction& first_catch_instr = accessor.InstructionAt(found_dex_pc);
            *has_no_move_exception = (first_catch_instr.Opcode() != Instruction::MOVE_EXCEPTION);
        }
        // Put the exception back.
        if (exception != nullptr) {
            self->SetException(exception.Get());
        }
        return found_dex_pc;
    }

    void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result,
        const char* shorty) {
        // Gate 1: this records what data_ contains before the normal invoke path has
        // performed class initialization, verification or entry-point dispatch. It
        // is deliberately restricted to the TLS-selected probe target.
        ArtMethod* const probe_target = runtime_snapshot::GetProbeTarget();
        if (UNLIKELY(probe_target == this)) {
            runtime_snapshot::CaptureMethod(this, runtime_snapshot::CaptureStage::kInvokePre);
        }

        if (UNLIKELY(__builtin_frame_address(0) < self->GetStackEnd())) {
            ThrowStackOverflowError(self);
            return;
        }

        if (kIsDebugBuild) {
            self->AssertThreadSuspensionIsAllowable();
            CHECK_EQ(ThreadState::kRunnable, self->GetState());
            CHECK_STREQ(GetInterfaceMethodIfProxy(kRuntimePointerSize)->GetShorty(), shorty);
        }

        // Push a transition back into managed code onto the linked list in thread.
        ManagedStack fragment;
        self->PushManagedStackFragment(&fragment);

        Runtime* runtime = Runtime::Current();
        // Call the invoke stub, passing everything as arguments.
        // If the runtime is not yet started or it is required by the debugger, then perform the
        // Invocation by the interpreter, explicitly forcing interpretation over JIT to prevent
        // cycling around the various JIT/Interpreter methods that handle method invocation.
        if (UNLIKELY(!runtime->IsStarted() ||
            (self->IsForceInterpreter() && !IsNative() && !IsProxyMethod() && IsInvokable()))) {
            if (IsStatic()) {
                art::interpreter::EnterInterpreterFromInvoke(
                    self, this, nullptr, args, result, /*stay_in_interpreter=*/ true);
            } else {
                mirror::Object* receiver =
                    reinterpret_cast<StackReference<mirror::Object>*>(&args[0])->AsMirrorPtr();
                art::interpreter::EnterInterpreterFromInvoke(
                    self, this, receiver, args + 1, result, /*stay_in_interpreter=*/ true);
            }
        } else {
            DCHECK_EQ(runtime->GetClassLinker()->GetImagePointerSize(), kRuntimePointerSize);

            constexpr bool kLogInvocationStartAndReturn = false;
            bool have_quick_code = GetEntryPointFromQuickCompiledCode() != nullptr;
            if (LIKELY(have_quick_code)) {
                if (kLogInvocationStartAndReturn) {
                    LOG(INFO) << StringPrintf(
                        "Invoking '%s' quick code=%p static=%d", PrettyMethod().c_str(),
                        GetEntryPointFromQuickCompiledCode(), static_cast<int>(IsStatic() ? 1 : 0));
                }

                // Ensure that we won't be accidentally calling quick compiled code when -Xint.
                if (kIsDebugBuild && runtime->GetInstrumentation()->IsForcedInterpretOnly()) {
                    CHECK(!runtime->UseJitCompilation());
                    const void* oat_quick_code =
                        (IsNative() || !IsInvokable() || IsProxyMethod() || IsObsolete())
                            ? nullptr
                            : GetOatMethodQuickCode(runtime->GetClassLinker()->GetImagePointerSize());
                    CHECK(oat_quick_code == nullptr || oat_quick_code != GetEntryPointFromQuickCompiledCode())
                        << "Don't call compiled code when -Xint " << PrettyMethod();
                }

                if (!IsStatic()) {
                    (*art_quick_invoke_stub)(this, args, args_size, self, result, shorty);
                } else {
                    (*art_quick_invoke_static_stub)(this, args, args_size, self, result, shorty);
                }
                if (UNLIKELY(self->GetException() == Thread::GetDeoptimizationException())) {
                    // Unusual case where we were running generated code and an
                    // exception was thrown to force the activations to be removed from the
                    // stack. Continue execution in the interpreter.
                    self->DeoptimizeWithDeoptimizationException(result);
                }
                if (kLogInvocationStartAndReturn) {
                    LOG(INFO) << StringPrintf("Returned '%s' quick code=%p", PrettyMethod().c_str(),
                        GetEntryPointFromQuickCompiledCode());
                }
            } else {
                LOG(INFO) << "Not invoking '" << PrettyMethod() << "' code=null";
                if (result != nullptr) {
                    result->SetJ(0);
                }
            }
        }

        // Pop transition.
        self->PopManagedStackFragment(fragment);
    }

    bool ArtMethod::IsSignaturePolymorphic() {
        // Methods with a polymorphic signature have constraints that they
        // are native and varargs and belong to either MethodHandle or VarHandle.
        if (!IsNative() || !IsVarargs()) {
            return false;
        }
        ObjPtr<mirror::ObjectArray<mirror::Class>> class_roots =
            Runtime::Current()->GetClassLinker()->GetClassRoots();
        ObjPtr<mirror::Class> cls = GetDeclaringClass();
        return (cls == GetClassRoot<mirror::MethodHandle>(class_roots) ||
            cls == GetClassRoot<mirror::VarHandle>(class_roots));
    }

    static uint32_t GetOatMethodIndexFromMethodIndex(const DexFile& dex_file,
        uint16_t class_def_idx,
        uint32_t method_idx) {
        ClassAccessor accessor(dex_file, class_def_idx);
        uint32_t class_def_method_index = 0u;
        for (const ClassAccessor::Method& method : accessor.GetMethods()) {
            if (method.GetIndex() == method_idx) {
                return class_def_method_index;
            }
            class_def_method_index++;
        }
        LOG(FATAL) << "Failed to find method index " << method_idx << " in " << dex_file.GetLocation();
        UNREACHABLE();
    }

// We use the method's DexFile and declaring class name to find the OatMethod for an obsolete
// method.  This is extremely slow but we need it if we want to be able to have obsolete native
// methods since we need this to find the size of its stack frames.
//
// NB We could (potentially) do this differently and rely on the way the transformation is applied
// in order to use the entrypoint to find this information. However, for debugging reasons (most
// notably making sure that new invokes of obsolete methods fail) we choose to instead get the data
// directly from the dex file.
    static const OatFile::OatMethod FindOatMethodFromDexFileFor(ArtMethod* method, bool* found)
    REQUIRES_SHARED(Locks::mutator_lock_) {
        DCHECK(method->IsObsolete() && method->IsNative());
        const DexFile* dex_file = method->GetDexFile();

        // recreate the class_def_index from the descriptor.
        std::string descriptor_storage;
        const dex::TypeId* declaring_class_type_id =
            dex_file->FindTypeId(method->GetDeclaringClass()->GetDescriptor(&descriptor_storage));
        CHECK(declaring_class_type_id != nullptr);
        dex::TypeIndex declaring_class_type_index = dex_file->GetIndexForTypeId(*declaring_class_type_id);
        const dex::ClassDef* declaring_class_type_def =
            dex_file->FindClassDef(declaring_class_type_index);
        CHECK(declaring_class_type_def != nullptr);
        uint16_t declaring_class_def_index = dex_file->GetIndexForClassDef(*declaring_class_type_def);

        size_t oat_method_index = GetOatMethodIndexFromMethodIndex(*dex_file,
            declaring_class_def_index,
            method->GetDexMethodIndex());

        OatFile::OatClass oat_class = OatFile::FindOatClass(*dex_file,
            declaring_class_def_index,
            found);
        if (!(*found)) {
            return OatFile::OatMethod::Invalid();
        }
        return oat_class.GetOatMethod(oat_method_index);
    }

    static const OatFile::OatMethod FindOatMethodFor(ArtMethod* method,
        PointerSize pointer_size,
        bool* found)
    REQUIRES_SHARED(Locks::mutator_lock_) {
        if (UNLIKELY(method->IsObsolete())) {
            // We shouldn't be calling this with obsolete methods except for native obsolete methods for
            // which we need to use the oat method to figure out how large the quick frame is.
            DCHECK(method->IsNative()) << "We should only be finding the OatMethod of obsolete methods in "
                                       << "order to allow stack walking. Other obsolete methods should "
                                       << "never need to access this information.";
            DCHECK_EQ(pointer_size, kRuntimePointerSize) << "Obsolete method in compiler!";
            return FindOatMethodFromDexFileFor(method, found);
        }
        // Although we overwrite the trampoline of non-static methods, we may get here via the resolution
        // method for direct methods (or virtual methods made direct).
        ObjPtr<mirror::Class> declaring_class = method->GetDeclaringClass();
        size_t oat_method_index;
        if (method->IsStatic() || method->IsDirect()) {
            // Simple case where the oat method index was stashed at load time.
            oat_method_index = method->GetMethodIndex();
        } else {
            // Compute the oat_method_index by search for its position in the declared virtual methods.
            oat_method_index = declaring_class->NumDirectMethods();
            bool found_virtual = false;
            for (ArtMethod& art_method : declaring_class->GetVirtualMethods(pointer_size)) {
                // Check method index instead of identity in case of duplicate method definitions.
                if (method->GetDexMethodIndex() == art_method.GetDexMethodIndex()) {
                    found_virtual = true;
                    break;
                }
                oat_method_index++;
            }
            CHECK(found_virtual) << "Didn't find oat method index for virtual method: "
                                 << method->PrettyMethod();
        }
        DCHECK_EQ(oat_method_index,
            GetOatMethodIndexFromMethodIndex(declaring_class->GetDexFile(),
                method->GetDeclaringClass()->GetDexClassDefIndex(),
                method->GetDexMethodIndex()));
        OatFile::OatClass oat_class = OatFile::FindOatClass(declaring_class->GetDexFile(),
            declaring_class->GetDexClassDefIndex(),
            found);
        if (!(*found)) {
            return OatFile::OatMethod::Invalid();
        }
        return oat_class.GetOatMethod(oat_method_index);
    }

    bool ArtMethod::EqualParameters(Handle<mirror::ObjectArray<mirror::Class>> params) {
        const DexFile* dex_file = GetDexFile();
        const auto& method_id = dex_file->GetMethodId(GetDexMethodIndex());
        const auto& proto_id = dex_file->GetMethodPrototype(method_id);
        const dex::TypeList* proto_params = dex_file->GetProtoParameters(proto_id);
        auto count = proto_params != nullptr ? proto_params->Size() : 0u;
        auto param_len = params != nullptr ? params->GetLength() : 0u;
        if (param_len != count) {
            return false;
        }
        auto* cl = Runtime::Current()->GetClassLinker();
        for (size_t i = 0; i < count; ++i) {
            dex::TypeIndex type_idx = proto_params->GetTypeItem(i).type_idx_;
            ObjPtr<mirror::Class> type = cl->ResolveType(type_idx, this);
            if (type == nullptr) {
                Thread::Current()->AssertPendingException();
                return false;
            }
            if (type != params->GetWithoutChecks(i)) {
                return false;
            }
        }
        return true;
    }

    const OatQuickMethodHeader* ArtMethod::GetOatQuickMethodHeader(uintptr_t pc) {
        // Our callers should make sure they don't pass the instrumentation exit pc,
        // as this method does not look at the side instrumentation stack.
        DCHECK_NE(pc, reinterpret_cast<uintptr_t>(GetQuickInstrumentationExitPc()));

        if (IsRuntimeMethod()) {
            return nullptr;
        }

        Runtime* runtime = Runtime::Current();
        const void* existing_entry_point = GetEntryPointFromQuickCompiledCode();
        CHECK(existing_entry_point != nullptr) << PrettyMethod() << "@" << this;
        ClassLinker* class_linker = runtime->GetClassLinker();

        if (existing_entry_point == GetQuickProxyInvokeHandler()) {
            DCHECK(IsProxyMethod() && !IsConstructor());
            // The proxy entry point does not have any method header.
            return nullptr;
        }

        // Check whether the current entry point contains this pc.
        if (!class_linker->IsQuickGenericJniStub(existing_entry_point) &&
            !class_linker->IsQuickResolutionStub(existing_entry_point) &&
            !class_linker->IsQuickToInterpreterBridge(existing_entry_point) &&
            existing_entry_point != GetQuickInstrumentationEntryPoint() &&
            existing_entry_point != GetInvokeObsoleteMethodStub()) {
            OatQuickMethodHeader* method_header =
                OatQuickMethodHeader::FromEntryPoint(existing_entry_point);

            if (method_header->Contains(pc)) {
                return method_header;
            }
        }

        if (OatQuickMethodHeader::IsNterpPc(pc)) {
            return OatQuickMethodHeader::NterpMethodHeader;
        }

        // Check whether the pc is in the JIT code cache.
        jit::Jit* jit = runtime->GetJit();
        if (jit != nullptr) {
            jit::JitCodeCache* code_cache = jit->GetCodeCache();
            OatQuickMethodHeader* method_header = code_cache->LookupMethodHeader(pc, this);
            if (method_header != nullptr) {
                DCHECK(method_header->Contains(pc));
                return method_header;
            } else {
                DCHECK(!code_cache->ContainsPc(reinterpret_cast<const void*>(pc)))
                    << PrettyMethod()
                    << ", pc=" << std::hex << pc
                    << ", entry_point=" << std::hex << reinterpret_cast<uintptr_t>(existing_entry_point)
                    << ", copy=" << std::boolalpha << IsCopied()
                    << ", proxy=" << std::boolalpha << IsProxyMethod();
            }
        }

        // The code has to be in an oat file.
        bool found;
        OatFile::OatMethod oat_method =
            FindOatMethodFor(this, class_linker->GetImagePointerSize(), &found);
        if (!found) {
            if (IsNative()) {
                // We are running the GenericJNI stub. The entrypoint may point
                // to different entrypoints or to a JIT-compiled JNI stub.
                DCHECK(class_linker->IsQuickGenericJniStub(existing_entry_point) ||
                    class_linker->IsQuickResolutionStub(existing_entry_point) ||
                    existing_entry_point == GetQuickInstrumentationEntryPoint() ||
                    (jit != nullptr && jit->GetCodeCache()->ContainsPc(existing_entry_point)))
                    << " entrypoint: " << existing_entry_point
                    << " size: " << OatQuickMethodHeader::FromEntryPoint(existing_entry_point)->GetCodeSize()
                    << " pc: " << reinterpret_cast<const void*>(pc);
                return nullptr;
            }
            // Only for unit tests.
            // TODO(ngeoffray): Update these tests to pass the right pc?
            return OatQuickMethodHeader::FromEntryPoint(existing_entry_point);
        }
        const void* oat_entry_point = oat_method.GetQuickCode();
        if (oat_entry_point == nullptr || class_linker->IsQuickGenericJniStub(oat_entry_point)) {
            DCHECK(IsNative()) << PrettyMethod();
            return nullptr;
        }

        OatQuickMethodHeader* method_header = OatQuickMethodHeader::FromEntryPoint(oat_entry_point);
        if (pc == 0) {
            // This is a downcall, it can only happen for a native method.
            DCHECK(IsNative());
            return method_header;
        }

        DCHECK(method_header->Contains(pc))
            << PrettyMethod()
            << " " << std::hex << pc << " " << oat_entry_point
            << " " << (uintptr_t)(method_header->GetCode() + method_header->GetCodeSize());
        return method_header;
    }

    const void* ArtMethod::GetOatMethodQuickCode(PointerSize pointer_size) {
        bool found;
        OatFile::OatMethod oat_method = FindOatMethodFor(this, pointer_size, &found);
        if (found) {
            return oat_method.GetQuickCode();
        }
        return nullptr;
    }

    bool ArtMethod::HasAnyCompiledCode() {
        if (IsNative() || !IsInvokable() || IsProxyMethod()) {
            return false;
        }

        // Check whether the JIT has compiled it.
        Runtime* runtime = Runtime::Current();
        jit::Jit* jit = runtime->GetJit();
        if (jit != nullptr && jit->GetCodeCache()->ContainsMethod(this)) {
            return true;
        }

        // Check whether we have AOT code.
        return GetOatMethodQuickCode(runtime->GetClassLinker()->GetImagePointerSize()) != nullptr;
    }

    void ArtMethod::SetIntrinsic(uint32_t intrinsic) {
        // Currently we only do intrinsics for static/final methods or methods of final
        // classes. We don't set kHasSingleImplementation for those methods.
        DCHECK(IsStatic() || IsFinal() || GetDeclaringClass()->IsFinal()) <<
                                                                          "Potential conflict with kAccSingleImplementation";
        static const int kAccFlagsShift = CTZ(kAccIntrinsicBits);
        DCHECK_LE(intrinsic, kAccIntrinsicBits >> kAccFlagsShift);
        uint32_t intrinsic_bits = intrinsic << kAccFlagsShift;
        uint32_t new_value = (GetAccessFlags() & ~kAccIntrinsicBits) | kAccIntrinsic | intrinsic_bits;
        if (kIsDebugBuild) {
            uint32_t java_flags = (GetAccessFlags() & kAccJavaFlagsMask);
            bool is_constructor = IsConstructor();
            bool is_synchronized = IsSynchronized();
            bool skip_access_checks = SkipAccessChecks();
            bool is_fast_native = IsFastNative();
            bool is_critical_native = IsCriticalNative();
            bool is_copied = IsCopied();
            bool is_miranda = IsMiranda();
            bool is_default = IsDefault();
            bool is_default_conflict = IsDefaultConflicting();
            bool is_compilable = IsCompilable();
            bool must_count_locks = MustCountLocks();
            // Recompute flags instead of getting them from the current access flags because
            // access flags may have been changed to deduplicate warning messages (b/129063331).
            uint32_t hiddenapi_flags = hiddenapi::CreateRuntimeFlags(this);
            SetAccessFlags(new_value);
            DCHECK_EQ(java_flags, (GetAccessFlags() & kAccJavaFlagsMask));
            DCHECK_EQ(is_constructor, IsConstructor());
            DCHECK_EQ(is_synchronized, IsSynchronized());
            DCHECK_EQ(skip_access_checks, SkipAccessChecks());
            DCHECK_EQ(is_fast_native, IsFastNative());
            DCHECK_EQ(is_critical_native, IsCriticalNative());
            DCHECK_EQ(is_copied, IsCopied());
            DCHECK_EQ(is_miranda, IsMiranda());
            DCHECK_EQ(is_default, IsDefault());
            DCHECK_EQ(is_default_conflict, IsDefaultConflicting());
            DCHECK_EQ(is_compilable, IsCompilable());
            DCHECK_EQ(must_count_locks, MustCountLocks());
            // Only DCHECK that we have preserved the hidden API access flags if the
            // original method was not in the SDK list. This is because the core image
            // does not have the access flags set (b/77733081).
            if ((hiddenapi_flags & kAccHiddenapiBits) != kAccPublicApi) {
                DCHECK_EQ(hiddenapi_flags, hiddenapi::GetRuntimeFlags(this)) << PrettyMethod();
            }
        } else {
            SetAccessFlags(new_value);
        }
    }

    void ArtMethod::SetNotIntrinsic() {
        if (!IsIntrinsic()) {
            return;
        }

        // Read the existing hiddenapi flags.
        uint32_t hiddenapi_runtime_flags = hiddenapi::GetRuntimeFlags(this);

        // Clear intrinsic-related access flags.
        ClearAccessFlags(kAccIntrinsic | kAccIntrinsicBits);

        // Re-apply hidden API access flags now that the method is not an intrinsic.
        SetAccessFlags(GetAccessFlags() | hiddenapi_runtime_flags);
        DCHECK_EQ(hiddenapi_runtime_flags, hiddenapi::GetRuntimeFlags(this));
    }

    void ArtMethod::CopyFrom(ArtMethod* src, PointerSize image_pointer_size) {
        memcpy(reinterpret_cast<void*>(this), reinterpret_cast<const void*>(src),
            Size(image_pointer_size));
        declaring_class_ = GcRoot<mirror::Class>(const_cast<ArtMethod*>(src)->GetDeclaringClass());

        // If the entry point of the method we are copying from is from JIT code, we just
        // put the entry point of the new method to interpreter or GenericJNI. We could set
        // the entry point to the JIT code, but this would require taking the JIT code cache
        // lock to notify it, which we do not want at this level.
        Runtime* runtime = Runtime::Current();
        if (runtime->UseJitCompilation()) {
            if (runtime->GetJit()->GetCodeCache()->ContainsPc(GetEntryPointFromQuickCompiledCode())) {
                SetEntryPointFromQuickCompiledCodePtrSize(
                    src->IsNative() ? GetQuickGenericJniStub() : GetQuickToInterpreterBridge(),
                    image_pointer_size);
            }
        }
        if (interpreter::IsNterpSupported() &&
            (GetEntryPointFromQuickCompiledCodePtrSize(image_pointer_size) ==
                interpreter::GetNterpEntryPoint())) {
            // If the entrypoint is nterp, it's too early to check if the new method
            // will support it. So for simplicity, use the interpreter bridge.
            SetEntryPointFromQuickCompiledCodePtrSize(GetQuickToInterpreterBridge(), image_pointer_size);
        }

        // Clear the data pointer, it will be set if needed by the caller.
        if (!src->HasCodeItem() && !src->IsNative()) {
            SetDataPtrSize(nullptr, image_pointer_size);
        }
        // Clear hotness to let the JIT properly decide when to compile this method.
        ResetCounter(runtime->GetJITOptions()->GetWarmupThreshold());
    }

    bool ArtMethod::IsImagePointerSize(PointerSize pointer_size) {
        // Hijack this function to get access to PtrSizedFieldsOffset.
        //
        // Ensure that PrtSizedFieldsOffset is correct. We rely here on usually having both 32-bit and
        // 64-bit builds.
        static_assert(std::is_standard_layout<ArtMethod>::value, "ArtMethod is not standard layout.");
        static_assert(
            (sizeof(void*) != 4) ||
                (offsetof(ArtMethod, ptr_sized_fields_) == PtrSizedFieldsOffset(PointerSize::k32)),
            "Unexpected 32-bit class layout.");
        static_assert(
            (sizeof(void*) != 8) ||
                (offsetof(ArtMethod, ptr_sized_fields_) == PtrSizedFieldsOffset(PointerSize::k64)),
            "Unexpected 64-bit class layout.");

        Runtime* runtime = Runtime::Current();
        if (runtime == nullptr) {
            return true;
        }
        return runtime->GetClassLinker()->GetImagePointerSize() == pointer_size;
    }

    std::string ArtMethod::PrettyMethod(ArtMethod* m, bool with_signature) {
        if (m == nullptr) {
            return "null";
        }
        return m->PrettyMethod(with_signature);
    }

    std::string ArtMethod::PrettyMethod(bool with_signature) {
        if (UNLIKELY(IsRuntimeMethod())) {
            std::string result = GetDeclaringClassDescriptor();
            result += '.';
            result += GetName();
            // Do not add "<no signature>" even if `with_signature` is true.
            return result;
        }
        ArtMethod* m =
            GetInterfaceMethodIfProxy(Runtime::Current()->GetClassLinker()->GetImagePointerSize());
        std::string res(m->GetDexFile()->PrettyMethod(m->GetDexMethodIndex(), with_signature));
        if (with_signature && m->IsObsolete()) {
            return "<OBSOLETE> " + res;
        } else {
            return res;
        }
    }

    std::string ArtMethod::JniShortName() {
        return GetJniShortName(GetDeclaringClassDescriptor(), GetName());
    }

    std::string ArtMethod::JniLongName() {
        std::string long_name;
        long_name += JniShortName();
        long_name += "__";

        std::string signature(GetSignature().ToString());
        signature.erase(0, 1);
        signature.erase(signature.begin() + signature.find(')'), signature.end());

        long_name += MangleForJni(signature);

        return long_name;
    }

    const char* ArtMethod::GetRuntimeMethodName() {
        Runtime* const runtime = Runtime::Current();
        if (this == runtime->GetResolutionMethod()) {
            return "<runtime internal resolution method>";
        } else if (this == runtime->GetImtConflictMethod()) {
            return "<runtime internal imt conflict method>";
        } else if (this == runtime->GetCalleeSaveMethod(CalleeSaveType::kSaveAllCalleeSaves)) {
            return "<runtime internal callee-save all registers method>";
        } else if (this == runtime->GetCalleeSaveMethod(CalleeSaveType::kSaveRefsOnly)) {
            return "<runtime internal callee-save reference registers method>";
        } else if (this == runtime->GetCalleeSaveMethod(CalleeSaveType::kSaveRefsAndArgs)) {
            return "<runtime internal callee-save reference and argument registers method>";
        } else if (this == runtime->GetCalleeSaveMethod(CalleeSaveType::kSaveEverything)) {
            return "<runtime internal save-every-register method>";
        } else if (this == runtime->GetCalleeSaveMethod(CalleeSaveType::kSaveEverythingForClinit)) {
            return "<runtime internal save-every-register method for clinit>";
        } else if (this == runtime->GetCalleeSaveMethod(CalleeSaveType::kSaveEverythingForSuspendCheck)) {
            return "<runtime internal save-every-register method for suspend check>";
        } else {
            return "<unknown runtime internal method>";
        }
    }

    void ArtMethod::SetCodeItem(const dex::CodeItem* code_item, bool is_compact_dex_code_item) {
        DCHECK(HasCodeItem());
        // We mark the lowest bit for the interpreter to know whether it's executing a
        // method in a compact or standard dex file.
        uintptr_t data =
            reinterpret_cast<uintptr_t>(code_item) | (is_compact_dex_code_item ? 1 : 0);
        SetDataPtrSize(reinterpret_cast<void*>(data), kRuntimePointerSize);
    }

// AssertSharedHeld doesn't work in GetAccessFlags, so use a NO_THREAD_SAFETY_ANALYSIS helper.
// TODO: Figure out why ASSERT_SHARED_CAPABILITY doesn't work.
    template <ReadBarrierOption kReadBarrierOption>
    ALWAYS_INLINE static inline void DoGetAccessFlagsHelper(ArtMethod* method)
    NO_THREAD_SAFETY_ANALYSIS {
        CHECK(method->IsRuntimeMethod() ||
            method->GetDeclaringClass<kReadBarrierOption>()->IsIdxLoaded() ||
            method->GetDeclaringClass<kReadBarrierOption>()->IsErroneous());
    }

}  // namespace art
