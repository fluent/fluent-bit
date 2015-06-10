# Draft for Monkey v1.6 Announcement

This is a draft document which lists the changes on this major version.

## Scheduler

- The scheduler is aware about protocol handlers.
- Remove array of connections, allocate space on demand.
- 'Connection' interface dropped and replaced by the Scheduler directly.

## Event Loop Interface

- On events notification, a Scheduler connection context is provided
  instead of the file descriptor.
- Event File Descriptor Table dropped.
- Event Loop now support backends (epoll for linux and kqueue for OSX).

## HTTP

- New HTTP Parser (rewritten and optimized)

## Plugins

- Architecture changes, now plugins can be build in static or dynamic mode.

## Build

- CMake: now Monkey builds using CMake, this change deprecated the old and
  dirty 'configure' script of 1200 lines. New CMake scripts exists for
  everything and a new configure script of 200 lines was added to work as
  a wrapper over the CMake build options provided by Monkey.

## Performance

- Monkey v1.6 is around ~33% faster than Monkey v1.5 when handling very
  small static files (1 byte).
