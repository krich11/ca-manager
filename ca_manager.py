#!/usr/bin/env python3
"""
Easy-KMS CA Manager
Standalone Certificate Authority management application
"""

import os
import sys
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import getpass
import tempfile

# Import prompt_toolkit for tab completion
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import PathCompleter
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False

class CAManager:
    def __init__(self):
        self.ca_dir = Path("ca")
        self.certs_dir = Path("certs")
        self.version = self.get_version()
        
        # Initialize prompt_toolkit session for tab completion
        if PROMPT_TOOLKIT_AVAILABLE:
            # Create a path completer that expands user paths
            completer = PathCompleter(expanduser=True)
            self.session = PromptSession(completer=completer)
        else:
            self.session = None
    
    def create_directories(self):
        """Create necessary directories"""
        self.ca_dir.mkdir(exist_ok=True)
        self.certs_dir.mkdir(exist_ok=True)
        (self.ca_dir / "newcerts").mkdir(exist_ok=True)
        (self.ca_dir / "private").mkdir(exist_ok=True)
        
    def prompt_ca_info(self):
        """Prompt user for CA information"""
        print("\n=== Certificate Authority Information ===")
        ca_info = {}
        
        ca_info['country'] = input("Country (2-letter code) [US]: ").strip() or "US"
        ca_info['state'] = input("State/Province [TX]: ").strip() or "TX"
        ca_info['locality'] = input("City/Locality [Houston]: ").strip() or "Houston"
        ca_info['organization'] = input("Organization [Easy-KMS]: ").strip() or "Easy-KMS"
        ca_info['organizational_unit'] = input("Organizational Unit [CA]: ").strip() or "CA"
        ca_info['common_name'] = input("Common Name [Easy-KMS Root CA]: ").strip() or "Easy-KMS Root CA"
        ca_info['email'] = input("Email [admin@easy-kms.com]: ").strip() or "admin@easy-kms.com"
        
        # Key size
        while True:
            try:
                key_size = input("RSA Key Size [4096]: ").strip() or "4096"
                ca_info['key_size'] = int(key_size)
                if ca_info['key_size'] not in [2048, 4096, 8192]:
                    print("Key size must be 2048, 4096, or 8192")
                    continue
                break
            except ValueError:
                print("Please enter a valid number")
        
        # Validity period
        while True:
            try:
                validity_years = input("Validity Period (years) [10]: ").strip() or "10"
                ca_info['validity_years'] = int(validity_years)
                if ca_info['validity_years'] < 1 or ca_info['validity_years'] > 50:
                    print("Validity must be between 1 and 50 years")
                    continue
                break
            except ValueError:
                print("Please enter a valid number")
        
        return ca_info
    
    def create_ca(self):
        """Create Certificate Authority"""
        if (self.ca_dir / "ca.crt").exists():
            print("CA already exists. Use 'Reset CA' option to recreate.")
            return
        
        print("\n=== Creating Certificate Authority ===")
        
        # Create directories
        self.create_directories()
        
        # Get CA information
        ca_info = self.prompt_ca_info()
        
        # Generate private key
        print("Generating CA private key...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=ca_info['key_size'],
            backend=default_backend()
        )
        
        # Save private key
        key_path = self.ca_dir / "private" / "ca.key"
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Create certificate
        print("Creating CA certificate...")
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, ca_info['country']),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ca_info['state']),
            x509.NameAttribute(NameOID.LOCALITY_NAME, ca_info['locality']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_info['organization']),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ca_info['organizational_unit']),
            x509.NameAttribute(NameOID.COMMON_NAME, ca_info['common_name']),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, ca_info['email']),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365*ca_info['validity_years'])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Save certificate
        cert_path = self.ca_dir / "ca.crt"
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Initialize CA database
        index_path = self.ca_dir / "index.txt"
        index_path.touch()
        
        serial_path = self.ca_dir / "serial"
        with open(serial_path, "w") as f:
            f.write("01")
        
        # Set permissions
        os.chmod(key_path, 0o600)
        os.chmod(cert_path, 0o644)
        
        print(f"✅ CA created successfully!")
        print(f"   Private key: {key_path}")
        print(f"   Certificate: {cert_path}")
    
    def prompt_cert_info(self, cert_type):
        """Prompt user for certificate information"""
        print(f"\n=== {cert_type} Certificate Information ===")
        cert_info = {}
        
        # Get CA info from certificate file
        ca_info = self.get_ca_info()
        
        # Use CA values as defaults
        default_country = ca_info.get('country', 'US')
        default_state = ca_info.get('state', 'TX')
        default_locality = ca_info.get('locality', 'Houston')
        default_organization = ca_info.get('organization', 'Easy-KMS')
        default_organizational_unit = ca_info.get('organizational_unit', 'Easy-KMS')
        default_email = ca_info.get('email', 'admin@easy-kms.com')
        
        cert_info['country'] = input(f"Country (2-letter code) [{default_country}]: ").strip() or default_country
        cert_info['state'] = input(f"State/Province [{default_state}]: ").strip() or default_state
        cert_info['locality'] = input(f"City/Locality [{default_locality}]: ").strip() or default_locality
        cert_info['organization'] = input(f"Organization [{default_organization}]: ").strip() or default_organization
        
        if cert_type == "KME":
            cert_info['organizational_unit'] = input(f"Organizational Unit [{default_organizational_unit}]: ").strip() or default_organizational_unit
            # Auto-increment KME name
            default_kme_name = self.get_next_cert_name("KME")
            cert_info['common_name'] = input(f"Common Name [{default_kme_name}]: ").strip() or default_kme_name
        else:  # SAE
            cert_info['organizational_unit'] = input(f"Organizational Unit [{default_organizational_unit}]: ").strip() or default_organizational_unit
            # Auto-increment SAE name
            default_sae_name = self.get_next_cert_name("SAE")
            cert_info['common_name'] = input(f"Common Name [{default_sae_name}]: ").strip() or default_sae_name
        
        cert_info['email'] = input(f"Email [{default_email}]: ").strip() or default_email
        
        # Key size (default 2048 for KME and SAE, but configurable)
        while True:
            try:
                key_size = input("RSA Key Size [2048]: ").strip() or "2048"
                cert_info['key_size'] = int(key_size)
                if cert_info['key_size'] not in [2048, 4096]:
                    print("Key size must be 2048 or 4096")
                    continue
                break
            except ValueError:
                print("Please enter a valid number")
        
        # Validity period (default 5 years)
        while True:
            try:
                validity_years = input("Validity Period (years) [5]: ").strip() or "5"
                cert_info['validity_years'] = int(validity_years)
                if cert_info['validity_years'] < 1 or cert_info['validity_years'] > 20:
                    print("Validity must be between 1 and 20 years")
                    continue
                break
            except ValueError:
                print("Please enter a valid number")
        
        return cert_info
    
    def get_ca_info(self):
        """Get CA information from the certificate file"""
        ca_cert_path = self.ca_dir / "ca.crt"
        if not ca_cert_path.exists():
            return {}
        
        try:
            with open(ca_cert_path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            ca_info = {}
            for attr in cert.subject:
                if attr.oid == NameOID.COUNTRY_NAME:
                    ca_info['country'] = attr.value
                elif attr.oid == NameOID.STATE_OR_PROVINCE_NAME:
                    ca_info['state'] = attr.value
                elif attr.oid == NameOID.LOCALITY_NAME:
                    ca_info['locality'] = attr.value
                elif attr.oid == NameOID.ORGANIZATION_NAME:
                    ca_info['organization'] = attr.value
                elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                    ca_info['organizational_unit'] = attr.value
                elif attr.oid == NameOID.COMMON_NAME:
                    ca_info['common_name'] = attr.value
                elif attr.oid == NameOID.EMAIL_ADDRESS:
                    ca_info['email'] = attr.value
            
            return ca_info
        except Exception as e:
            print(f"Error reading CA certificate: {e}")
            return {}
    
    def get_next_cert_name(self, cert_type):
        """Get the next available certificate name for the given type"""
        cert_dir = self.certs_dir / cert_type.lower()
        if not cert_dir.exists():
            return f"{cert_type}_001"
        
        # Find existing certificates of this type
        existing_names = []
        for cert_file in cert_dir.glob("*.crt"):
            cert_name = cert_file.stem  # filename without extension
            if cert_name.startswith(f"{cert_type.lower()}_"):
                try:
                    # Extract number from name like "kme_001"
                    number = int(cert_name.split('_')[1])
                    existing_names.append(number)
                except (IndexError, ValueError):
                    pass
        
        if not existing_names:
            return f"{cert_type}_001"
        
        # Find the next available number
        next_number = max(existing_names) + 1
        return f"{cert_type}_{next_number:03d}"
    
    def create_certificate(self, cert_type):
        """Create KME or SAE certificate"""
        if not (self.ca_dir / "ca.crt").exists():
            print("CA must be created first!")
            return
        
        print(f"\n=== Creating {cert_type} Certificate ===")
        
        # Get certificate information
        cert_info = self.prompt_cert_info(cert_type)
        
        # Generate private key
        print(f"Generating {cert_type} private key...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=cert_info['key_size'],
            backend=default_backend()
        )
        
        # Create certificate signing request
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, cert_info['country']),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, cert_info['state']),
            x509.NameAttribute(NameOID.LOCALITY_NAME, cert_info['locality']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, cert_info['organization']),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, cert_info['organizational_unit']),
            x509.NameAttribute(NameOID.COMMON_NAME, cert_info['common_name']),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, cert_info['email']),
        ])
        
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Load CA private key and certificate
        ca_key_path = self.ca_dir / "private" / "ca.key"
        ca_cert_path = self.ca_dir / "ca.crt"
        
        with open(ca_key_path, 'rb') as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        
        with open(ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Create certificate
        print(f"Signing {cert_type} certificate...")
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365*cert_info['validity_years'])
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        ).sign(ca_private_key, hashes.SHA256(), default_backend())
        
        # Create output directory
        output_dir = self.certs_dir / cert_type.lower()
        output_dir.mkdir(exist_ok=True)
        
        # Save private key
        key_filename = f"{cert_info['common_name'].lower()}.key"
        key_path = output_dir / key_filename
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save certificate
        cert_filename = f"{cert_info['common_name'].lower()}.crt"
        cert_path = output_dir / cert_filename
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Update CA database
        self.update_ca_database(cert, cert_info['common_name'].lower(), cert_type)
        
        # Set permissions
        os.chmod(key_path, 0o600)
        os.chmod(cert_path, 0o644)
        
        print(f"✅ {cert_type} certificate created successfully!")
        print(f"   Private key: {key_path}")
        print(f"   Certificate: {cert_path}")
    
    def sign_csr(self):
        """Sign a Certificate Signing Request (CSR) and output certificate in PEM format"""
        if not (self.ca_dir / "ca.crt").exists():
            print("CA must be created first!")
            return
        
        print("\n=== Sign Certificate Signing Request ===")
        
        # Get CSR filename
        csr_filename = self.smart_input("Enter CSR filename: ")
        if not csr_filename:
            print("CSR filename is required!")
            return
        
        # Expand shell shortcuts like ~ for home directory
        csr_filename_expanded = os.path.expanduser(os.path.expandvars(csr_filename))
        csr_path = Path(csr_filename_expanded)
        if not csr_path.exists():
            print(f"CSR file '{csr_filename_expanded}' not found!")
            return
        
        # Load CA private key and certificate
        ca_key_path = self.ca_dir / "private" / "ca.key"
        ca_cert_path = self.ca_dir / "ca.crt"
        
        try:
            with open(ca_key_path, 'rb') as f:
                ca_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            
            with open(ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        except Exception as e:
            print(f"Error loading CA files: {e}")
            return
        
        # Load and parse CSR
        try:
            with open(csr_path, 'rb') as f:
                csr_data = f.read()
            
            # Try to load as PEM first
            try:
                csr = x509.load_pem_x509_csr(csr_data, default_backend())
            except ValueError:
                # Try to load as DER
                try:
                    csr = x509.load_der_x509_csr(csr_data, default_backend())
                except ValueError:
                    print("Error: Invalid CSR format. File must be in PEM or DER format.")
                    return
            
            print(f"✅ CSR loaded successfully")
            print(f"   Subject: {csr.subject}")
            
        except Exception as e:
            print(f"Error loading CSR: {e}")
            return
        
        # Get validity period
        while True:
            try:
                validity_years = input("Validity Period (years) [5]: ").strip() or "5"
                validity_years = int(validity_years)
                if validity_years < 1 or validity_years > 20:
                    print("Validity must be between 1 and 20 years")
                    continue
                break
            except ValueError:
                print("Please enter a valid number")
        
        # Create certificate
        print("Signing certificate...")
        try:
            # Start building the certificate
            cert_builder = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365*validity_years)
            )
            
            # Preserve extensions from CSR
            extensions_added = set()
            
            # Process each extension from the CSR
            for extension in csr.extensions:
                extension_oid = extension.oid
                extension_value = extension.value
                is_critical = extension.critical
                
                print(f"   Processing extension: {extension_oid}")
                
                # Handle different extension types
                if extension_oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    # Subject Alternative Names
                    cert_builder = cert_builder.add_extension(extension_value, critical=is_critical)
                    extensions_added.add(extension_oid)
                    print(f"     Added SAN: {extension_value}")
                    
                elif extension_oid == x509.oid.ExtensionOID.EXTENDED_KEY_USAGE:
                    # Extended Key Usage
                    cert_builder = cert_builder.add_extension(extension_value, critical=is_critical)
                    extensions_added.add(extension_oid)
                    print(f"     Added EKU: {extension_value}")
                    
                elif extension_oid == x509.oid.ExtensionOID.KEY_USAGE:
                    # Key Usage - preserve from CSR but ensure it's not CA-related
                    # Create a new KeyUsage that preserves the CSR settings but removes CA capabilities
                    csr_key_usage = extension_value
                    
                    # Handle encipher_only and decipher_only based on key_agreement
                    if csr_key_usage.key_agreement:
                        new_key_usage = x509.KeyUsage(
                            digital_signature=csr_key_usage.digital_signature,
                            key_encipherment=csr_key_usage.key_encipherment,
                            key_cert_sign=False,  # Always False for end-entity certs
                            crl_sign=False,       # Always False for end-entity certs
                            content_commitment=csr_key_usage.content_commitment,
                            data_encipherment=csr_key_usage.data_encipherment,
                            key_agreement=csr_key_usage.key_agreement,
                            encipher_only=csr_key_usage.encipher_only,
                            decipher_only=csr_key_usage.decipher_only
                        )
                    else:
                        new_key_usage = x509.KeyUsage(
                            digital_signature=csr_key_usage.digital_signature,
                            key_encipherment=csr_key_usage.key_encipherment,
                            key_cert_sign=False,  # Always False for end-entity certs
                            crl_sign=False,       # Always False for end-entity certs
                            content_commitment=csr_key_usage.content_commitment,
                            data_encipherment=csr_key_usage.data_encipherment,
                            key_agreement=False,
                            encipher_only=False,
                            decipher_only=False
                        )
                    
                    cert_builder = cert_builder.add_extension(new_key_usage, critical=is_critical)
                    extensions_added.add(extension_oid)
                    print(f"     Added Key Usage (modified): {new_key_usage}")
                    
                elif extension_oid == x509.oid.ExtensionOID.BASIC_CONSTRAINTS:
                    # Basic Constraints - ensure it's not a CA
                    csr_basic_constraints = extension_value
                    new_basic_constraints = x509.BasicConstraints(
                        ca=False,  # Always False for end-entity certs
                        path_length=None
                    )
                    cert_builder = cert_builder.add_extension(new_basic_constraints, critical=True)
                    extensions_added.add(extension_oid)
                    print(f"     Added Basic Constraints (modified): {new_basic_constraints}")
                    
                elif extension_oid == x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                    # Subject Key Identifier - preserve from CSR
                    cert_builder = cert_builder.add_extension(extension_value, critical=is_critical)
                    extensions_added.add(extension_oid)
                    print(f"     Added Subject Key Identifier")
                    
                elif extension_oid == x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                    # Authority Key Identifier - we'll add our own
                    print(f"     Skipping Authority Key Identifier (will add CA's)")
                    
                else:
                    # For any other extensions, preserve them as-is
                    cert_builder = cert_builder.add_extension(extension_value, critical=is_critical)
                    extensions_added.add(extension_oid)
                    print(f"     Added extension: {extension_oid}")
            
            # Add required extensions if not present in CSR
            if x509.oid.ExtensionOID.BASIC_CONSTRAINTS not in extensions_added:
                cert_builder = cert_builder.add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True
                )
                print("   Added Basic Constraints (default)")
            
            if x509.oid.ExtensionOID.KEY_USAGE not in extensions_added:
                cert_builder = cert_builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=True,
                        key_cert_sign=False,
                        crl_sign=False,
                        content_commitment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True
                )
                print("   Added Key Usage (default)")
            
            if x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER not in extensions_added:
                cert_builder = cert_builder.add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                    critical=False
                )
                print("   Added Subject Key Identifier (default)")
            
            # Always add Authority Key Identifier
            cert_builder = cert_builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
                critical=False
            )
            print("   Added Authority Key Identifier")
            
            # Sign the certificate
            cert = cert_builder.sign(ca_private_key, hashes.SHA256(), default_backend())
            
            # Update CA database
            self.update_ca_database(cert, csr_path.stem, "CSR")
            
            # Output certificate in PEM format
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            print("\n" + "="*60)
            print("SIGNED CERTIFICATE (PEM FORMAT)")
            print("="*60)
            print(cert_pem.decode('utf-8'))
            print("="*60)
            
            # Ask if user wants to save to file
            save_to_file = input("\nSave certificate to file? (y/n) [n]: ").strip().lower()
            if save_to_file in ['y', 'yes']:
                default_filename = f"{csr_path.stem}_signed.crt"
                output_filename = self.smart_input(f"Output filename [{default_filename}]: ") or default_filename
                
                # Expand shell shortcuts like ~ for home directory
                output_filename_expanded = os.path.expanduser(os.path.expandvars(output_filename))
                
                with open(output_filename_expanded, "wb") as f:
                    f.write(cert_pem)
                
                print(f"✅ Certificate saved to: {output_filename_expanded}")
            
        except Exception as e:
            print(f"Error signing certificate: {e}")
            return
    
    def export_p12(self):
        """Export certificate as password-protected P12 file"""
        # Find all certificates
        certs = []
        
        # Check KME certificates
        kme_dir = self.certs_dir / "kme"
        if kme_dir.exists():
            for cert_file in kme_dir.glob("*.crt"):
                key_file = kme_dir / f"{cert_file.stem}.key"
                if key_file.exists():
                    certs.append({
                        'name': cert_file.stem,
                        'type': 'KME',
                        'cert_path': str(cert_file),
                        'key_path': str(key_file)
                    })
        
        # Check SAE certificates
        sae_dir = self.certs_dir / "sae"
        if sae_dir.exists():
            for cert_file in sae_dir.glob("*.crt"):
                key_file = sae_dir / f"{cert_file.stem}.key"
                if key_file.exists():
                    certs.append({
                        'name': cert_file.stem,
                        'type': 'SAE',
                        'cert_path': str(cert_file),
                        'key_path': str(key_file)
                    })
        
        if not certs:
            print("No certificates to export!")
            return
        
        print("\n=== Export Certificate as P12 ===")
        
        # List available certificates
        print("Available certificates:")
        for i, cert_data in enumerate(certs, 1):
            print(f"  {i}. {cert_data['name']} ({cert_data['type']})")
        
        # Select certificate
        while True:
            try:
                choice = int(input(f"\nSelect certificate (1-{len(certs)}): "))
                if 1 <= choice <= len(certs):
                    cert_data = certs[choice - 1]
                    break
                else:
                    print("Invalid selection")
            except ValueError:
                print("Please enter a valid number")
        
        # Get export filename
        default_filename = f"{cert_data['name']}.p12"
        filename = self.smart_input(f"Export filename [{default_filename}]: ") or default_filename
        
        # Expand shell shortcuts like ~ for home directory
        filename_expanded = os.path.expanduser(os.path.expandvars(filename))
        
        # Get password
        password = getpass.getpass("Enter P12 password: ")
        if not password:
            print("Password is required!")
            return
        
        # Export P12
        try:
            cmd = [
                'openssl', 'pkcs12', '-export',
                '-in', cert_data['cert_path'],
                '-inkey', cert_data['key_path'],
                '-out', filename_expanded,
                '-passout', f'pass:{password}'
            ]
            
            subprocess.run(cmd, check=True, capture_output=True)
            print(f"✅ P12 file exported: {filename_expanded}")
            
        except subprocess.CalledProcessError as e:
            print(f"Error exporting P12: {e}")
        except Exception as e:
            print(f"Error: {e}")
    
    def list_certificates(self):
        """List all certificates"""
        print("\n=== Certificate List ===")
        
        # Check CA
        ca_cert_path = self.ca_dir / "ca.crt"
        if ca_cert_path.exists():
            ca_info = self.get_ca_info()
            print("Certificate Authority:")
            print(f"  Common Name: {ca_info.get('common_name', 'Unknown')}")
            print(f"  Organization: {ca_info.get('organization', 'Unknown')}")
            print()
        
        # Check KME certificates
        kme_dir = self.certs_dir / "kme"
        if kme_dir.exists() and list(kme_dir.glob("*.crt")):
            print("KME Certificates:")
            for cert_file in kme_dir.glob("*.crt"):
                print(f"  {cert_file.stem}")
            print()
        
        # Check SAE certificates
        sae_dir = self.certs_dir / "sae"
        if sae_dir.exists() and list(sae_dir.glob("*.crt")):
            print("SAE Certificates:")
            for cert_file in sae_dir.glob("*.crt"):
                print(f"  {cert_file.stem}")
            print()
        
        if not (ca_cert_path.exists() or 
                (kme_dir.exists() and list(kme_dir.glob("*.crt"))) or 
                (sae_dir.exists() and list(sae_dir.glob("*.crt")))):
            print("No certificates created yet.")
    
    def reset_ca(self):
        """Reset CA and all certificates"""
        print("\n=== Reset CA ===")
        confirm = input("This will delete ALL certificates and CA. Are you sure? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Reset cancelled.")
            return
        
        # Remove directories
        if self.ca_dir.exists():
            shutil.rmtree(self.ca_dir)
        if self.certs_dir.exists():
            shutil.rmtree(self.certs_dir)
        
        print("✅ CA and all certificates reset.")
    
    def get_version(self):
        """Get version from VERSION file"""
        try:
            version_file = Path(__file__).parent / "VERSION"
            if version_file.exists():
                with open(version_file, 'r') as f:
                    return f.read().strip()
            else:
                return "0.0.0"
        except Exception:
            return "0.0.0"
    
    def smart_input(self, prompt):
        """Smart input with tab completion if available"""
        if self.session:
            try:
                return self.session.prompt(prompt).strip()
            except Exception as e:
                # Fallback to regular input if prompt_toolkit fails
                print(f"Warning: Tab completion failed, using regular input: {e}")
                return input(prompt).strip()
        else:
            return input(prompt).strip()
    
    def get_next_serial_number(self):
        """Get the next available serial number"""
        serial_path = self.ca_dir / "serial"
        if not serial_path.exists():
            return "01"
        
        try:
            with open(serial_path, "r") as f:
                current_serial = f.read().strip()
            
            # Convert to integer, increment, and format as hex
            next_serial = int(current_serial, 16) + 1
            return f"{next_serial:02X}"
        except Exception:
            return "01"
    
    def update_serial_number(self, serial_number):
        """Update the serial number file"""
        serial_path = self.ca_dir / "serial"
        with open(serial_path, "w") as f:
            f.write(serial_number)
    
    def update_ca_database(self, cert, cert_name, cert_type):
        """Update the CA database with certificate information"""
        try:
            # Get serial number
            serial_number = self.get_next_serial_number()
            
            # Format: Status,ExpirationDate,RevocationDate,SerialNumber,FileName,SubjectDN
            # Status: V=Valid, R=Revoked, E=Expired
            status = "V"  # Valid
            
            # Get expiration date
            expiration_date = cert.not_valid_after.strftime("%y%m%d%H%M%SZ")
            
            # Revocation date (empty for valid certificates)
            revocation_date = ""
            
            # Serial number (hex format)
            serial_hex = f"{cert.serial_number:02X}"
            
            # File name (for CSR-signed certs, we don't have a local file)
            filename = f"{cert_type}_{cert_name}.crt"
            
            # Subject DN
            subject_dn = self.format_dn(cert.subject)
            
            # Create database entry
            db_entry = f"{status}\t{expiration_date}\t{revocation_date}\t{serial_hex}\t{filename}\t{subject_dn}\n"
            
            # Append to index.txt
            index_path = self.ca_dir / "index.txt"
            with open(index_path, "a") as f:
                f.write(db_entry)
            
            # Update serial number
            self.update_serial_number(serial_number)
            
            print(f"   Certificate recorded in CA database (Serial: {serial_hex})")
            
        except Exception as e:
            print(f"Warning: Could not update CA database: {e}")
    
    def format_dn(self, name):
        """Format Distinguished Name for database entry"""
        dn_parts = []
        for attr in name:
            if attr.oid == NameOID.COUNTRY_NAME:
                dn_parts.append(f"C={attr.value}")
            elif attr.oid == NameOID.STATE_OR_PROVINCE_NAME:
                dn_parts.append(f"ST={attr.value}")
            elif attr.oid == NameOID.LOCALITY_NAME:
                dn_parts.append(f"L={attr.value}")
            elif attr.oid == NameOID.ORGANIZATION_NAME:
                dn_parts.append(f"O={attr.value}")
            elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                dn_parts.append(f"OU={attr.value}")
            elif attr.oid == NameOID.COMMON_NAME:
                dn_parts.append(f"CN={attr.value}")
            elif attr.oid == NameOID.EMAIL_ADDRESS:
                dn_parts.append(f"emailAddress={attr.value}")
        
        return "/".join(dn_parts)
    
    def show_menu(self):
        """Show main menu"""
        print("\n" + "="*50)
        print(f"Easy-KMS CA Manager v{self.version}")
        print("="*50)
        print("1. Create Certificate Authority")
        print("2. Create KME Certificate")
        print("3. Create SAE Certificate")
        print("4. Sign CSR")
        print("5. Export P12 Certificate")
        print("6. List Certificates")
        print("7. Reset CA")
        print("q. Exit")
        print("="*50)
    
    def run(self):
        """Run the CA manager"""
        while True:
            self.show_menu()
            choice = input("\nSelect option: ").strip()
            
            if choice == 'q':
                print("Goodbye!")
                break
            elif choice == '1':
                self.create_ca()
            elif choice == '2':
                self.create_certificate("KME")
            elif choice == '3':
                self.create_certificate("SAE")
            elif choice == '4':
                self.sign_csr()
            elif choice == '5':
                self.export_p12()
            elif choice == '6':
                self.list_certificates()
            elif choice == '7':
                self.reset_ca()
            else:
                print("Invalid option. Please try again.")
            
            input("\nPress Enter to continue...")

def check_requirements():
    """Check if all required packages are installed"""
    missing_packages = []
    
    # Check cryptography
    try:
        import cryptography
    except ImportError:
        missing_packages.append("cryptography")
    
    # Check prompt_toolkit
    try:
        import prompt_toolkit
    except ImportError:
        missing_packages.append("prompt_toolkit")
    
    if missing_packages:
        print("\n" + "="*60)
        print("❌ MISSING REQUIRED PACKAGES")
        print("="*60)
        print("The following packages are required but not installed:")
        for package in missing_packages:
            print(f"  - {package}")
        print("\nTo install all required packages, run:")
        print("  pip install -r requirements.txt")
        print("\nOr install individually:")
        for package in missing_packages:
            print(f"  pip install {package}")
        print("="*60)
        return False
    
    return True

def main():
    """Main function"""
    try:
        # Check requirements first
        if not check_requirements():
            sys.exit(1)
        
        ca_manager = CAManager()
        ca_manager.run()
    except KeyboardInterrupt:
        print("\n\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
