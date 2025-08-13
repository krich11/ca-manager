# Easy-KMS CA Manager

A standalone Certificate Authority management application for creating and managing KME and SAE certificates.

## Features

- **Certificate Authority Creation**: Create a new CA with customizable parameters
- **KME Certificate Management**: Generate KME certificates signed by the CA
- **SAE Certificate Management**: Generate SAE certificates signed by the CA
- **P12 Export**: Export certificates as password-protected P12 files
- **Certificate Listing**: View all created certificates
- **CA Reset**: Reset the entire CA and all certificates

## Installation

1. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the CA Manager**:
   ```bash
   python ca_manager.py
   ```

## Usage

### 1. Create Certificate Authority

First, create a Certificate Authority that will sign all other certificates:

```
1. Create Certificate Authority
```

You'll be prompted for:
- Country, State, Locality, Organization
- Organizational Unit, Common Name, Email
- RSA Key Size (2048, 4096, or 8192 bits)
- Validity Period (1-50 years)

### 2. Create KME Certificate

Generate a KME certificate signed by your CA:

```
2. Create KME Certificate
```

You'll be prompted for certificate details similar to the CA creation.

### 3. Create SAE Certificate

Generate an SAE certificate signed by your CA:

```
3. Create SAE Certificate
```

### 4. Export P12 Certificate

Export any certificate as a password-protected P12 file:

```
4. Export P12 Certificate
```

This is useful for importing certificates into other systems.

### 5. List Certificates

View all created certificates and their details:

```
5. List Certificates
```

### 6. Reset CA

Completely reset the CA and all certificates:

```
6. Reset CA
```

⚠️ **Warning**: This will delete ALL certificates and the CA.

## Directory Structure

After running the CA Manager, you'll have:

```
ca-manager/
├── ca/                    # CA directory
│   ├── ca.crt            # CA certificate
│   ├── private/
│   │   └── ca.key        # CA private key
│   ├── index.txt         # Certificate database
│   └── serial            # Serial number counter
├── certs/                # Certificates directory
│   ├── kme/              # KME certificates
│   └── sae/              # SAE certificates
├── ca_config.json        # Configuration file
└── *.p12                 # Exported P12 files
```

## Security Notes

- Private keys are stored with 600 permissions (owner read/write only)
- Certificates are stored with 644 permissions (owner read/write, others read)
- CA private key should be kept secure and backed up
- P12 exports are password-protected

## Integration with Easy-KMS

The certificates created by this CA Manager can be used with the Easy-KMS project:

1. Copy the `ca/ca.crt` to your Easy-KMS `certs/` directory
2. Copy KME certificates to `certs/kme/`
3. Copy SAE certificates to `certs/sae/`
4. Update your Easy-KMS configuration to use these certificates

## Future Plans

This CA Manager is designed to be extracted into its own repository for standalone use across multiple projects.
