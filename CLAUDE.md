# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Raptor-EDR is a modern Endpoint Detection and Response (EDR) platform built in Go, designed with a defensive security focus. The project follows a Go-hexagonal architecture pattern, combining the standard Go project layout with dependency inversion principles.

### Architecture Philosophy

The project implements a "Go-Hexagonal" hybrid model:
- Uses standard Go project layout (/cmd for executables, /internal for private code, /pkg for shared libraries)
- Applies hexagonal architecture principles with dependency inversion
- Adopts a Monorepo structure for all components (agents, services, shared libraries)

### Core Components

Based on the architectural documentation, the EDR platform consists of:

1. **Cross-Platform Agent** - Endpoint monitoring and data collection
   - Linux sensor layer using eBPF (via cilium/ebpf library)
   - Windows sensor layer using ETW (Event Tracing for Windows)
   - Cross-platform system information via shirou/gopsutil

2. **Backend Microservices** - Distributed processing platform
   - Ingest-Gateway: Receives telemetry from agents
   - Enrichment-Service: Adds context to raw telemetry
   - Real-time-Analytics-Service: Applies detection rules
   - Persistence-Service: Stores data in appropriate databases
   - Batch-Analytics-Service: Complex behavioral analysis
   - API-Gateway: External interface
   - Identity-Service: Authentication and authorization

## Technology Stack

### Core Libraries
- **Configuration**: spf13/viper (hierarchical config with hot reload)
- **Logging**: rs/zerolog (structured logging, high performance)
- **Web Framework**: gin-gonic/gin (for API services)
- **Communication**: gRPC with mTLS (agent-server protocol)
- **Message Bus**: NATS JetStream (for data pipeline)

### Platform-Specific
- **Linux Kernel Monitoring**: cilium/ebpf (pure Go, no CGO)
- **Windows API**: golang.org/x/sys/windows + community wrappers
- **System Info**: shirou/gopsutil (cross-platform)

### Data Storage (Polyglot Persistence)
- **Time Series**: ClickHouse or TimescaleDB (telemetry events)
- **Graph Database**: Neo4j or ArangoDB (attack chain relationships)
- **Relational**: PostgreSQL (platform metadata, users)

## Development Commands

Since this is an early-stage project, standard Go commands apply:

```bash
# Build all components
go build ./...

# Run tests
go test ./...

# Run specific tests with verbose output
go test -v ./internal/...

# Cross-compile for Linux (from any platform)
GOOS=linux GOARCH=amd64 go build -o agent-linux ./cmd/agent

# Cross-compile for Windows
GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent

# Format code
go fmt ./...

# Run linter (if available)
golangci-lint run

# Tidy dependencies
go mod tidy
```

## Expected Project Structure

Based on the architectural blueprint, expect this structure to develop:

```
/
├── cmd/                    # Main applications
│   ├── agent/             # Cross-platform EDR agent
│   ├── ingest-gateway/    # Telemetry ingestion service  
│   ├── enrichment/        # Data enrichment service
│   ├── analytics/         # Real-time detection service
│   └── api-gateway/       # External API service
├── internal/              # Private application code
│   ├── agent/            # Agent implementation
│   │   ├── sensor/       # Platform-specific data collection
│   │   ├── config/       # Configuration management
│   │   ├── comms/        # gRPC communication
│   │   └── tasking/      # Command execution
│   ├── platform/         # Infrastructure adapters
│   │   ├── storage/      # Database adapters
│   │   └── messaging/    # Message bus adapters
│   └── services/         # Business logic for each microservice
├── pkg/                  # Shared libraries
│   ├── logger/           # Centralized logging setup
│   ├── models/           # Data models and events
│   └── security/         # Security primitives
├── proto/                # gRPC protocol definitions
├── configs/              # Configuration files
└── docs/                 # Architecture and design documents
```

## Security Focus

This is a defensive security project. When working on this codebase:

- **Allowed**: Security analysis, detection rules, vulnerability explanations, defensive tools, security documentation
- **Never create**: Malicious code, attack tools, or exploitation utilities
- **Focus on**: Detection, monitoring, threat hunting, incident response capabilities

## MITRE ATT&CK Alignment

The EDR platform is designed around MITRE ATT&CK framework coverage. When implementing detection capabilities, reference the tactics and techniques that each telemetry source addresses.

## Key Development Principles

1. **Pure Go Preference**: Avoid CGO when possible for easier cross-compilation
2. **Performance Critical**: Minimize overhead on monitored endpoints
3. **Filtering First**: Implement smart filtering to reduce noise and data volume
4. **Context Rich**: Capture process relationships, command lines, and execution chains
5. **Correlation Capable**: Design for cross-event and cross-time correlation

## Testing Strategy

When tests are implemented, focus on:
- Unit tests for core business logic
- Integration tests for data pipelines
- Platform-specific sensor testing on target OS
- Performance benchmarks for high-frequency collection

## Deployment Considerations

The architecture supports:
- Kubernetes deployment for backend services
- Docker containerization
- Cloud-native scaling patterns
- On-premises deployment options

## Configuration Management

All services use viper for configuration with this hierarchy:
1. Code defaults
2. Configuration files (YAML/TOML)
3. Environment variables (EDR_* prefix)
4. Command line flags