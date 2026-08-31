#ifndef ART_RUNTIME_RUNTIME_SNAPSHOT_RUNTIME_SNAPSHOT_H_
#define ART_RUNTIME_RUNTIME_SNAPSHOT_RUNTIME_SNAPSHOT_H_

#include <cstdint>

#include "base/locks.h"

namespace art {

class ArtMethod;

namespace runtime_snapshot {

#define ART_RUNTIME_SNAPSHOT_HIDDEN __attribute__((visibility("hidden")))

// The same ArtMethod can be observed at more than one gate. Keeping the stage
// in the record makes it possible for the offline repair tool to choose the
// latest/most useful snapshot without guessing where it came from.
enum class CaptureStage : uint8_t {
  kDexImage = 0,
  kInvokePre = 1,
  kSwitchInterpreterEntry = 2,
  kNterpEntry = 3,
  // Keep the original values stable so existing .rpr files remain readable.
  // This gate is later than a shell quick trampoline but earlier than q2i's
  // EnsureInitialized(), making it the safe terminal stage for static methods
  // and <clinit> in a live application process.
  kQuickToInterpreterBridge = 4,
  // ArtMethod::Invoke() can bypass quick entrypoints when the runtime forces
  // interpretation.  This gate runs before receiver decoding and before the
  // direct interpreter path calls EnsureInitialized().
  kInterpreterFromInvoke = 5,
};

// The target is thread-local: normal application invocations on this or other
// threads must never be mistaken for an active runtime probe.
ART_RUNTIME_SNAPSHOT_HIDDEN ArtMethod* GetProbeTarget();
ART_RUNTIME_SNAPSHOT_HIDDEN void SetProbeTarget(ArtMethod* method);

class ScopedProbeTarget final {
 public:
  explicit ScopedProbeTarget(ArtMethod* target)
      : previous_(GetProbeTarget()) {
    SetProbeTarget(target);
  }

  ~ScopedProbeTarget() {
    SetProbeTarget(previous_);
  }

  ScopedProbeTarget(const ScopedProbeTarget&) = delete;
  ScopedProbeTarget& operator=(const ScopedProbeTarget&) = delete;

 private:
  ArtMethod* const previous_;
};

// StartWriter() duplicates fd, so the caller keeps ownership of the original.
// StopWriter() drains records, writes the commit footer, fsyncs and closes only
// ART's duplicate. It returns true only when every queued record and the footer
// reached the output successfully.
ART_RUNTIME_SNAPSHOT_HIDDEN bool StartWriter(int fd);
ART_RUNTIME_SNAPSHOT_HIDDEN bool StopWriter();
ART_RUNTIME_SNAPSHOT_HIDDEN bool IsWriterStarted();

// Copies every byte needed by the writer before returning. The writer thread
// therefore never dereferences ArtMethod/DexFile/CodeItem pointers later.
ART_RUNTIME_SNAPSHOT_HIDDEN bool CaptureMethod(ArtMethod* method, CaptureStage stage)
    REQUIRES_SHARED(Locks::mutator_lock_);

}  // namespace runtime_snapshot
}  // namespace art

#endif  // ART_RUNTIME_RUNTIME_SNAPSHOT_RUNTIME_SNAPSHOT_H_
