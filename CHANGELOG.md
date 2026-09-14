# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** `kos::Sender::new` and `kos::Receiver::new` take an
  `InstanceId`. KOS15 is analysed as one extension per global `delta`; every
  instance sharing a `delta` must now name a distinct id, and the two parties of
  one instance must name the same one. Instances are separated by PRG stream, so
  `InstanceId::SOLO` reproduces the previous derivation byte for byte and a
  `delta` driven by a single instance stays wire compatible.
- **Breaking:** `kos::Receiver` no longer implements `Default`. A receiver
  cannot be built without stating its `InstanceId`, and defaulting that id is
  the mistake the id exists to prevent. Use `kos::Receiver::new`.
