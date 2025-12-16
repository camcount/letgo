# Implementation Plan

- [x] 1. Set up project structure and core interfaces

  - Create directory structure for network-mapper module
  - Define core interfaces (ScannerEngine, PortScanner, ServiceDetector, OSFingerprinter)
  - Set up testing framework with testify/quick for property-based testing
  - _Requirements: 9.4, 9.5_

- [x] 1.1 Create core data models and types

  - Implement ScanConfig, ScanResult, HostResult, PortResult structs
  - Define ScanType, PortState, and other enums
  - Create ProgressInfo and ScanStatistics types
  - _Requirements: 1.3, 6.3, 8.1_

- [x] 1.2 Write property test for core data model validation

  - **Property 14: Result Persistence**
  - **Validates: Requirements 6.1, 6.3**

- [x] 2. Implement basic port scanning functionality

  - Create PortScanner interface implementation
  - Implement TCP SYN scanning using raw sockets
  - Implement TCP Connect scanning using standard connections
  - Implement UDP scanning with protocol-specific probes
  - _Requirements: 5.1, 5.2, 5.3_

- [x] 2.1 Add port scanning validation and error handling

  - Implement port range validation (1-65535)
  - Add connection timeout and retry logic
  - Handle network errors gracefully with logging
  - _Requirements: 1.5, 2.5_

- [x] 2.2 Write property test for port range compliance

  - **Property 2: Port Range Compliance**
  - **Validates: Requirements 1.2**

- [x] 2.3 Write property test for scan type implementation

  - **Property 12: Scan Type Implementation**
  - **Validates: Requirements 5.1, 5.2, 5.3**

- [x] 2.4 Write property test for error resilience

  - **Property 7: Error Resilience**
  - **Validates: Requirements 1.5, 2.5**

- [x] 3. Implement target resolution and CIDR support

  - Create target parser for IP addresses, hostnames, and CIDR ranges
  - Implement CIDR range expansion to individual hosts
  - Add DNS resolution with error handling
  - _Requirements: 1.1, 2.1_

- [x] 3.1 Write property test for target scanning completeness

  - **Property 1: Target Scanning Completeness**
  - **Validates: Requirements 1.1**

- [x] 3.2 Write property test for CIDR range expansion

  - **Property 4: CIDR Range Expansion**
  - **Validates: Requirements 2.1**

- [x] 4. Implement concurrent scanning engine

  - Create ScannerEngine with goroutine-based concurrency
  - Implement connection limiting and resource management
  - Add scan state management (running, paused, stopped)
  - _Requirements: 2.2, 2.3, 8.3, 8.4_

- [x] 4.1 Write property test for connection limiting

  - **Property 5: Connection Limiting**
  - **Validates: Requirements 2.3**

- [x] 4.2 Write property test for scan control operations

  - **Property 18: Scan Control Operations**
  - **Validates: Requirements 8.3, 8.4**

- [x] 5. Add progress monitoring and real-time updates

  - Implement ProgressMonitor with callback system
  - Calculate scan rate, ETA, and completion percentage
  - Add real-time progress display in console interface
  - _Requirements: 2.4, 8.1, 8.2_

- [x] 5.1 Write property test for progress reporting

  - **Property 6: Progress Reporting**
  - **Validates: Requirements 2.4, 8.1, 8.2**

- [x] 6. Implement service detection and banner grabbing

  - Create ServiceDetector with service signature database
  - Implement banner grabbing for common protocols (HTTP, SSH, FTP, etc.)
  - Add service version detection using regex patterns
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 6.1 Write property test for service detection activation

  - **Property 8: Service Detection Activation**
  - **Validates: Requirements 3.1, 3.2**

- [x] 6.2 Write property test for service information completeness

  - **Property 9: Service Information Completeness**
  - **Validates: Requirements 3.3**

- [x] 7. Implement OS fingerprinting capabilities

  - Create OSFingerprinter with TCP/IP stack analysis
  - Implement OS signature database and matching algorithms
  - Add confidence scoring for OS detection results
  - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [x] 7.1 Write property test for OS detection execution

  - **Property 10: OS Detection Execution**
  - **Validates: Requirements 4.1**

- [x] 7.2 Write property test for OS information completeness

  - **Property 11: OS Information Completeness**
  - **Validates: Requirements 4.2**

- [x] 8. Create scan profiles and timing configurations

  - Implement predefined scan profiles (quick, comprehensive, stealth, vulnerability)
  - Add custom profile creation and persistence
  - Implement timing profiles for stealth scanning
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 5.4_

- [x] 8.1 Write property test for stealth mode behavior

  - **Property 13: Stealth Mode Behavior**
  - **Validates: Requirements 5.4**

- [x] 8.2 Write property test for profile configuration persistence

  - **Property 17: Profile Configuration Persistence**
  - **Validates: Requirements 7.5**

- [x] 9. Implement result management and export functionality

  - Create ResultManager with multiple output format support (JSON, XML, text)
  - Implement result organization by host with nested port/service data
  - Add result loading and merging capabilities
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

- [x] 9.1 Write property test for export format support

  - **Property 15: Export Format Support**
  - **Validates: Requirements 6.2**

- [x] 9.2 Write property test for result organization

  - **Property 16: Result Organization**
  - **Validates: Requirements 6.4**

- [x] 10. Checkpoint - Make sure all tests are passing

  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Integrate with console menu system

  - Add Network Mapper option to main console menu
  - Create interactive scanning interface with user prompts
  - Implement scan configuration wizard
  - _Requirements: 9.1_

- [x] 11.1 Add integration with other Letgo modules

  - Implement export options for discovered web services
  - Add integration hooks for endpoint scanning and brute force attacks
  - Create target export functionality for other modules
  - _Requirements: 9.2, 9.3_

- [x] 11.2 Write property test for integration compatibility

  - **Property 19: Integration Compatibility**
  - **Validates: Requirements 9.2, 9.3**

- [x] 12. Implement file system integration

  - Use Letgo's existing data directory structure
  - Follow established configuration file patterns
  - Implement result storage in network-mapper subdirectory
  - _Requirements: 9.4, 9.5_

- [x] 12.1 Write property test for file system consistency

  - **Property 20: File System Consistency**
  - **Validates: Requirements 9.4, 9.5**

- [x] 13. Add comprehensive error handling and validation

  - Implement input validation for all user inputs
  - Add graceful degradation for resource constraints
  - Create comprehensive logging system
  - _Requirements: 1.5, 2.5_

- [x] 13.1 Write unit tests for error handling

  - Test network error scenarios and recovery
  - Test input validation edge cases
  - Test resource limit handling
  - _Requirements: 1.5, 2.5_

- [x] 14. Create default port lists and service signatures

  - Implement top 1000 common ports list
  - Create comprehensive service signature database
  - Add OS fingerprint database
  - _Requirements: 1.4, 3.2, 4.1_

- [x] 14.1 Write unit tests for default configurations

  - Test default port list contains exactly top 1000 ports
  - Test service signature matching accuracy
  - Test OS fingerprint database completeness
  - _Requirements: 1.4, 3.2, 4.1_

- [x] 15. Implement scan result completeness validation

  - Ensure all scan results include required information
  - Add result validation and consistency checks
  - Implement scan result summary generation
  - _Requirements: 1.3, 3.3, 4.2_

- [x] 15.1 Write property test for scan result completeness

  - **Property 3: Scan Result Completeness**
  - **Validates: Requirements 1.3**

- [x] 16. Add performance optimization and resource management

  - Implement memory usage monitoring for large scans
  - Add file descriptor management for concurrent connections
  - Optimize scanning algorithms for speed and accuracy
  - _Requirements: 2.2, 2.3_

- [x] 16.1 Write unit tests for performance and resource management

  - Test memory usage stays within bounds
  - Test file descriptor cleanup
  - Test scanning performance benchmarks
  - _Requirements: 2.2, 2.3_

- [x] 17. Final Checkpoint - Make sure all tests are passing

  - Ensure all tests pass, ask the user if questions arise.
