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

class CAManager:
    def __init__(self):
        self.ca_dir = Path("ca")
        self.certs_dir = Path("certs")
    
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
        
        # Set permissions
        os.chmod(key_path, 0o600)
        os.chmod(cert_path, 0o644)
        
        print(f"✅ {cert_type} certificate created successfully!")
        print(f"   Private key: {key_path}")
        print(f"   Certificate: {cert_path}")
    
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
        filename = input(f"Export filename [{default_filename}]: ").strip() or default_filename
        
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
                '-out', filename,
                '-passout', f'pass:{password}'
            ]
            
            subprocess.run(cmd, check=True, capture_output=True)
            print(f"✅ P12 file exported: {filename}")
            
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
    
    def show_menu(self):
        """Show main menu"""
        print("\n" + "="*50)
        print("Easy-KMS CA Manager")
        print("="*50)
        print("1. Create Certificate Authority")
        print("2. Create KME Certificate")
        print("3. Create SAE Certificate")
        print("4. Export P12 Certificate")
        print("5. List Certificates")
        print("6. Reset CA")
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
                self.export_p12()
            elif choice == '5':
                self.list_certificates()
            elif choice == '6':
                self.reset_ca()
            else:
                print("Invalid option. Please try again.")
            
            input("\nPress Enter to continue...")

def main():
    """Main function"""
    try:
        ca_manager = CAManager()
        ca_manager.run()
    except KeyboardInterrupt:
        print("\n\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
