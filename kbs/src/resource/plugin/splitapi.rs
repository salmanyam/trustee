// SPDX-License-Identifier: Apache-2.0
//
// Copyright (c) 2024 by IBM Inc.

//! The nebula plugin allows the KBS to deliver resources required to create
//! an encrypted overlay network between nodes using [Nebula](https://github.com/slackhq/nebula),
//!
//! Splitapi plugin provisions credential resources for a sandbox and sends sever specific credentials
//! to the sandbox to initiate Split API proxy server and establish a secure tunnel between tenant 
//! and the API proxy server.

use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509Name, X509, X509ReqBuilder, X509Req};
use openssl::x509::extension::BasicConstraints;
use openssl::x509::extension::KeyUsage;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::extension::AuthorityKeyIdentifier;
use openssl::pkey::PKey;
use openssl::x509::X509Builder;
use openssl::hash::MessageDigest;
use std::fs::File;
use std::io::Write;
use std::io::Read;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use std::path::{Path, PathBuf};
use std::error::Error;

use anyhow::{anyhow, bail, Context, Result};
use serde_qs;
use std::ffi::OsString;
use std::io;
use std::fs;
use std::sync::Arc;
use tokio::sync::RwLock;

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::sync::Mutex;

use super::{Plugin, PluginBuild};


pub const PLUGIN_NAME: &str = "splitapi";

//const NEBULA_CONFIG_PATH: &str = "/etc/kbs/plugin/nebula-config.toml";
//const NEBULA_CONFIG_PATH: &str = "/home/salman/pr/trustee/kbs/config/plugin/nebula-config.toml";
const CREDENTIAL_MAPPING_FILENAME: &str = "sandbox-credential-mapping.json";

const CA_KEY_FILENAME: &str = "ca.key";
const CA_CRT_FILENAME: &str = "ca.pem";
const CLIENT_KEY_FILENAME: &str = "client.key";
const CLIENT_CSR_FILENAME: &str = "client.csr";
const CLIENT_CRT_FILENAME: &str = "client.pem";
const SERVER_KEY_FILENAME: &str = "server.key";
const SERVER_CSR_FILENAME: &str = "server.csr";
const SERVER_CRT_FILENAME: &str = "server.pem";

const CREDENTIAL_KEY_SIZE: u32 = 2048;

// Use lazy_static to initialize the DIRECTORY_MANAGER only once
lazy_static! {
    static ref DIRECTORY_MANAGER: Arc<Mutex<Option<DirectoryManager>>> = Arc::new(Mutex::new(None));
}

// Initialize the singleton with the provided file path
fn init_directory_manager(file_path: PathBuf) -> std::io::Result<()> {
    let mut manager = DIRECTORY_MANAGER.lock().unwrap();
    
    // Attempt to load the DirectoryManager from the file
    match DirectoryManager::load_from_file(file_path) {
        Ok(loaded_manager) => {
            *manager = Some(loaded_manager);
        }
        Err(_e) => {
            // Initialize a new manager
            *manager = Some(DirectoryManager::new());

            // TODO: check specific errors (file not found or something else) 
            // and handle those specific errors
            // bail if there's relevant condition
        }
    }

    Ok(())
}

// Get a reference to the singleton
fn get_directory_manager() -> Arc<Mutex<Option<DirectoryManager>>> {
    Arc::clone(&DIRECTORY_MANAGER)
}


/// Plugin configuration
/// It is documented in the nebula plugin config toml file
#[derive(Debug, Default, serde::Deserialize)]
pub struct SplitapiPluginConfig {
    // TODO: potential fields are (1) default credential expire time
    // (2) always generate
}

impl PluginBuild for SplitapiPluginConfig {
    fn get_plugin_name(&self) -> &str {
        PLUGIN_NAME
    }

    fn create_plugin(&self, work_dir: &str) -> Result<Arc<RwLock<dyn Plugin + Send + Sync>>> {
        let workdir = PathBuf::from(work_dir);

        // Create the splitplugin work directory if it does not exist
        if !workdir.exists() {
            fs::create_dir_all(workdir.clone())
                .with_context(|| format!("Create {} dir", workdir.display()))?;
            
            log::info!("Splitapi plugin directory created = {}", work_dir);
        }

        // Initialize directory manager with the content from a file
        let mapping_file: PathBuf = PathBuf::from(work_dir).as_path().join(CREDENTIAL_MAPPING_FILENAME);
        init_directory_manager(mapping_file.clone())?;
        log::info!("Directory manager loaded the data from file: {}", mapping_file.display());
 

        // Initialize the credentail provisioner
        let cp = CredentailProvisioner {
            work_dir: PathBuf::from(work_dir),
            mapping_filename: mapping_file, 
            directory_manager: get_directory_manager(),
        };

        Ok(Arc::new(RwLock::new(SplitapiPlugin { cp })) as Arc<RwLock<dyn Plugin + Send + Sync>>)
    }
}

/// It has the fields to store the mapping between a sandbox name or id 
/// to a unique directory created by the directory manager
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DirectoryInfo {
    id: String,
    ip: String,
    name: String,
    path: PathBuf, 
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct DirectoryManager {
    // Maps sandbox name to DirectoryInfo
    dir_map: HashMap<String, DirectoryInfo>, 
}


/// Responsible for generating, storing, or loading unique directory
/// names for each sandbox. That means it creates a unique directory
/// for a sandbox (if the directory does not already exist), and stores
/// the mapping between the sandbox name (or id) to a file
impl DirectoryManager {
    fn new() -> Self {
        DirectoryManager {
            dir_map: HashMap::new(),
        }
    }

    // Generate a unique directory name from the fields
    fn generate_unique_dirname(id: &str, ip: &str, name: &str) -> String {
        format!("{}_{}_{}", name, ip, id)
    }

    // Create a directory and store it in the HashMap
    fn create_directory(&mut self, work_dir: &Path, params: &SplitapiSandboxParams) -> Result<DirectoryInfo> {
        let directory_name = DirectoryManager::generate_unique_dirname(
            &params.id, 
            &params.ip, 
            &params.name
        );
        let directory_path: PathBuf = PathBuf::from(work_dir).as_path().join(&directory_name);

        // Create the directory
        fs::create_dir_all(&directory_path.clone())
            .with_context(|| format!("Create {} dir", directory_path.display()))?;

        log::info!("Directory {} created", directory_name);

        // Store directory info in the HashMap
        let dir_info = DirectoryInfo {
            id: params.id.clone(),
            ip: params.ip.clone(),
            name: params.name.clone(),
            path: directory_path.clone(),
        };

        self.dir_map.insert(params.name.clone(), dir_info.clone());

        Ok(dir_info)
    }

    // Retrieve the directory info by name
    fn get_directory(&self, name: &str) -> Option<&DirectoryInfo> {
        self.dir_map.get(name)
    }

    // Function to write DirectoryInfo to a JSON file
    fn write_to_file(&self, dir_info: &DirectoryInfo, file_path: &PathBuf) -> io::Result<()> {
        let file = OpenOptions::new().append(true).create(true).open(file_path)?;
        let mut writer = std::io::BufWriter::new(file);
        
        // Serialize the DirectoryInfo entry and append it to the file with a newline delimiter
        serde_json::to_writer(&mut writer, &dir_info)?;
        writer.write_all(b"\n")?; // Add a newline to separate entries

        Ok(())
    }

    // Load the directory data from a JSON file
    fn load_from_file(file_path: PathBuf) -> Result<Self> {

        log::info!("Loading directory info: {}", file_path.display());

        let file = File::open(file_path)?;
        let reader = BufReader::new(file);

        // Create a new DirectoryManager and populate its HashMap
        let mut manager = DirectoryManager::new();


        for line in reader.lines() {
            let line = line?;
            let entry: DirectoryInfo = serde_json::from_str(&line)?;
            log::info!("{:?}", entry);
            manager.dir_map.insert(entry.name.clone(), entry);
        }

        Ok(manager)
    }
}

/// Parameters taken by the "splitapi" plugin to store the certificates
/// generated for the sandbox by combining the IP address, sandbox name,
/// sandbox ID to create an unique directory for the sandbox
#[derive(Debug, PartialEq, serde::Deserialize)]
struct SplitapiSandboxParams {
    id: String,
    ip: String,
    name: String,
}

impl From<&SplitapiSandboxParams> for Vec<OsString> {
    fn from(params: &SplitapiSandboxParams) -> Self {
        let mut v: Vec<OsString> = Vec::new();

        v.push("-id".into());
        v.push((&params.id).into());
        v.push("-name".into());
        v.push((&params.name).into());
        v.push("-ip".into());
        v.push((&params.ip.to_string()).into());

        v
    }
}


#[derive(Debug, serde::Serialize)]
pub struct ServerCredentialResource {
    pub key: Vec<u8>,
    pub crt: Vec<u8>,
    pub ca_crt: Vec<u8>,
}


/// Credentials (keys and certs for ca, server, and client) stored 
/// in work_dir/sandbox-specific-directory
#[derive(Debug)]
struct CredentialBundle {
    //work_dir: PathBuf,
    key_size: u32,
    ca_key: PathBuf,
    ca_crt: PathBuf,
    client_key: PathBuf,
    client_csr: PathBuf,
    client_crt: PathBuf,
    server_key: PathBuf,
    server_csr: PathBuf,
    server_crt: PathBuf
}

impl CredentialBundle {
    pub fn new(workdir: PathBuf) -> Result<Self> {
        let ca_key: PathBuf = workdir.as_path().join(CA_KEY_FILENAME);
        let ca_crt: PathBuf = workdir.as_path().join(CA_CRT_FILENAME);

        let client_key: PathBuf = workdir.as_path().join(CLIENT_KEY_FILENAME);
        let client_csr: PathBuf = workdir.as_path().join(CLIENT_CSR_FILENAME);
        let client_crt: PathBuf = workdir.as_path().join(CLIENT_CRT_FILENAME);

        let server_key: PathBuf = workdir.as_path().join(SERVER_KEY_FILENAME);
        let server_csr: PathBuf = workdir.as_path().join(SERVER_CSR_FILENAME);
        let server_crt: PathBuf = workdir.as_path().join(SERVER_CRT_FILENAME);

        Ok(Self {
            //work_dir: workdir,
            key_size: CREDENTIAL_KEY_SIZE,
            ca_key,
            ca_crt,
            client_key,
            client_csr,
            client_crt,
            server_key,
            server_csr,
            server_crt
        })
    }

    /// Run several steps for generate all the keys and certificates
    pub fn generate(
        &self,
        params: &SplitapiSandboxParams,
    ) -> Result<&Self> {
        //let mut args: Vec<OsString> = Vec::from(params);
        log::info!("Params {:?}", params);

        match self.generate_private_key(&self.ca_key, self.key_size) {
            Ok(_) => println!("CA key generation succeeded and saved to {}.", self.ca_key.display()),
            Err(e) => eprintln!("CA key generation failed: {}", e),
        }

        match self.generate_ca_cert(&self.ca_crt, &self.ca_key) {
            Ok(_) => println!("CA self-signed certificate generated and saved to {}.", self.ca_crt.display()),
            Err(e) => eprintln!("CA self-signed certificate generation failed: {}", e),
        }

        match self.generate_private_key(&self.server_key, self.key_size) {
            Ok(_) => println!("Server key generation succeeded and saved to {}.", self.server_key.display()),
            Err(e) => eprintln!("Server key generation failed: {}", e),
        }

        let server_common_name = "server";
        match self.generate_csr(&self.server_csr, &self.server_key, server_common_name) {
            Ok(_) => println!("Server csr generation succeeded and saved to {}.", self.server_csr.display()),
            Err(e) => eprintln!("Server csr generation failed: {}", e),
        }

        match self.generate_cert(&self.server_crt, &self.server_csr, &self.ca_crt, &self.ca_key) {
            Ok(_) => println!("Server cert generation succeeded and saved to {}.", self.server_crt.display()),
            Err(e) => eprintln!("Server cert generation failed: {}", e),
        }

        match self.generate_private_key(&self.client_key, self.key_size) {
            Ok(_) => println!("Client key generation succeeded and saved to {}.", self.client_key.display()),
            Err(e) => eprintln!("Client key generation failed: {}", e),
        }

        let client_common_name = "client";
        match self.generate_csr(&self.client_csr, &self.client_key, client_common_name) {
            Ok(_) => println!("Client CSR generation succeeded and saved to {}.", self.client_csr.display()),
            Err(e) => eprintln!("Client CSR generation failed: {}", e),
        }

        match self.generate_cert(&self.client_crt, &self.client_csr, &self.ca_crt, &self.ca_key) {
            Ok(_) => println!("Client cert generation succeeded and saved to {}.", self.client_crt.display()),
            Err(e) => eprintln!("Client cert generation failed: {}", e),
        }

        Ok(self)
    }

    fn generate_private_key(
        &self, 
        ca_key_path: &PathBuf, 
        key_size: u32
    ) -> Result<(), Box<dyn Error>> {
        // Generate RSA key
        let rsa = Rsa::generate(key_size).expect("Failed to generate RSA key");
        let pkey = PKey::from_rsa(rsa).expect("Failed to create PKey from RSA");
    
        // Write the private key to a file
        let private_key_pem = pkey.private_key_to_pem_pkcs8()?;
        let mut file = File::create(ca_key_path.as_path())?;
        file.write_all(&private_key_pem)?;
    
        Ok(())
    }

    fn build_x509_name(
        &self, 
        common_name: &str
    ) -> Result<X509Name, Box<dyn std::error::Error>> {
        // Define certificate details
        let country = "AA";
        let state = "Default State";
        let locality = "Default City";
        let organization = "Default Organization";
        let org_unit = "Default Unit";
    
        // Build X.509 name
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("C", country)?;
        name_builder.append_entry_by_text("ST", state)?;
        name_builder.append_entry_by_text("L", locality)?;
        name_builder.append_entry_by_text("O", organization)?;
        name_builder.append_entry_by_text("OU", org_unit)?;
        name_builder.append_entry_by_text("CN", common_name)?;
        let name = name_builder.build();
    
        Ok(name)
    }
    
    fn generate_ca_cert(
        &self, 
        crt_path: &PathBuf, 
        ca_key_path: &PathBuf
    ) -> Result<(), Box<dyn Error>> {
        // Read the private key from file
        let mut file = File::open(ca_key_path.as_path())?;
        let mut key_pem = Vec::new();
        file.read_to_end(&mut key_pem)?;
        let rsa = Rsa::private_key_from_pem(&key_pem)?;
        let pkey = PKey::from_rsa(rsa)?;
    
        // Build X.509 name
        let common_name = "grpc-tls CA";
        let name = self.build_x509_name(common_name)?;
    
        // Build the X.509 certificate
        let mut x509_builder = X509Builder::new()?;
        x509_builder.set_subject_name(&name)?;
        x509_builder.set_issuer_name(&name)?;
        x509_builder.set_pubkey(&pkey)?;
    
        // Set certificate validity period
        x509_builder.set_not_before(&Asn1Time::days_from_now(0).expect("Failed to set not before")).expect("Failed to set not before");
        x509_builder.set_not_after(&Asn1Time::days_from_now(3650).expect("Failed to set not after")).expect("Failed to set not after");
     
        // Sign the certificate
        x509_builder.sign(&pkey, MessageDigest::sha256())?;
        let x509 = x509_builder.build();
    
        // Write the certificate to a file
        let crt_pem = x509.to_pem()?;
        let mut crt_file = File::create(crt_path.as_path())?;
        crt_file.write_all(&crt_pem)?;
    
        Ok(())
    }
    
    fn generate_csr(
        &self, 
        csr_path: &PathBuf, 
        private_key_path: &PathBuf, 
        common_name: &str
    ) -> Result<(), Box<dyn Error>> {
        
        // Read the private key from file
        let mut file = File::open(private_key_path.as_path())?;
        let mut key_pem = Vec::new();
        file.read_to_end(&mut key_pem)?;
        let rsa = Rsa::private_key_from_pem(&key_pem)?;
        let pkey = PKey::from_rsa(rsa)?;
    
        // Build X.509 name
        let name = self.build_x509_name(common_name)?;
       
        // Create a new X.509 certificate signing request (CSR)
        let mut csr_builder = X509ReqBuilder::new()?;
        csr_builder.set_subject_name(&name)?;
        csr_builder.set_pubkey(&pkey)?;
        csr_builder.sign(&pkey, MessageDigest::sha256())?;
       
        let csr = csr_builder.build();
    
        // Write CSR to a file
        let mut csr_file = File::create(csr_path.as_path())?;
        csr_file.write_all(&csr.to_pem()?)?;
    
        Ok(())
    }
    
    fn generate_cert(
        &self, 
        crt_path: &PathBuf, 
        csr_path: &PathBuf, 
        ca_crt_path: &PathBuf, 
        ca_key_path: &PathBuf
    ) -> Result<(), Box<dyn Error>> {
        // Step 1: Read the CSR
        let mut csr_file = File::open(csr_path.as_path())?;
        let mut csr_data = vec![];
        csr_file.read_to_end(&mut csr_data)?;
        let csr = X509Req::from_pem(&csr_data)?;
    
        // Step 2: Read the CA PEM
        let mut ca_file = File::open(ca_crt_path.as_path())?;
        let mut ca_data = vec![];
        ca_file.read_to_end(&mut ca_data)?;
        let ca_cert = X509::from_pem(&ca_data)?;
    
        // Step 3: Read the CA Key
        let mut ca_key_file = File::open(ca_key_path.as_path())?;
        let mut ca_key_data = vec![];
        ca_key_file.read_to_end(&mut ca_key_data)?;
        let ca_key = PKey::private_key_from_pem(&ca_key_data)?;
    
        // Step 5: Create the server certificate
        let mut builder = X509Builder::new()?;
    
        // Set the version of the certificate
        builder.set_version(2)?;
    
        // Set the serial number
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        builder.set_serial_number(&serial_number)?;
    
        // Set the subject name from the CSR
        builder.set_subject_name(csr.subject_name())?;
        //TODO: add sandbox IP in the subject
    
        // Set the issuer name from the CA certificate
        builder.set_issuer_name(ca_cert.subject_name())?;
    
        // Set the public key from the CSR 
        let public_key = csr.public_key()?; 
        builder.set_pubkey(&public_key)?;
    
        // Set the certificate validity period 
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?; 
        let not_after = openssl::asn1::Asn1Time::days_from_now(3650)?; 
        builder.set_not_before(&not_before)?; 
        builder.set_not_after(&not_after)?;
    
        // Add extensions from the certificate extensions file 
        builder.append_extension(BasicConstraints::new().critical().build()?)?; 
        builder.append_extension(KeyUsage::new().digital_signature().key_encipherment().build()?)?; 
        builder.append_extension(SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?)?; 
        builder.append_extension(AuthorityKeyIdentifier::new().keyid(false).issuer(false).build(&builder.x509v3_context(Some(&ca_cert), None))?)?;
    
        // Sign the certificate with the CA key 
        builder.sign(&ca_key, MessageDigest::sha256())?; 
        
        // Write the server certificate to a file 
        let server_crt = builder.build().to_pem()?; 
        let mut crt_file = File::create(crt_path.as_path())?;
        crt_file.write_all(&server_crt)?;
    
        Ok(())
    }
}

/// Credentail Provisioner mainstains the directory mapping,
/// generates the credentials, and stores them in a unique 
/// directory for each sandbox
#[derive(Debug, Default)]
struct CredentailProvisioner {
    work_dir: PathBuf,
    mapping_filename: PathBuf,
    directory_manager: Arc<Mutex<Option<DirectoryManager>>>,
}

impl CredentailProvisioner {
    
    pub fn get_server_credential(
        &self, 
        params: &SplitapiSandboxParams
    ) -> Result<Vec<u8>> {
        // Try locking the directory manager
        let mut manager_guard = self.directory_manager.lock().map_err(|e| {
            anyhow!("Failed to lock directory manager: {}", e)
        })?;

        if let Some(manager) = manager_guard.as_mut() {
            let dir_info: DirectoryInfo;

            if let Some(existing_dir_info) = manager.get_directory(&params.name) {
            
                log::info!("Found existing directory: {:?}", existing_dir_info.path);
                dir_info = existing_dir_info.clone();

                //TODO: check if the credentails are already in there
                // send the existing credentials if they are not expired
            
            } else {
                let new_dir_info = manager.create_directory(self.work_dir.as_path(), &params)?;
                log::info!("New directory created: {:?}", new_dir_info);
                
                manager.write_to_file(&new_dir_info, &self.mapping_filename)?;
            
                dir_info = new_dir_info;
            }

            // Generate the credentials (keys and certs for ca, server, and client)
            let cred_bundle = CredentialBundle::new(dir_info.path)?;
            cred_bundle.generate(params)?;

            // Return the server specific credentials
            let resource = ServerCredentialResource {
                key: fs::read(cred_bundle.server_key.as_path())
                    .with_context(|| format!("read {}", cred_bundle.server_key.display()))?,
                crt: fs::read(cred_bundle.server_crt.as_path())
                    .with_context(|| format!("read {}", cred_bundle.server_crt.display()))?,
                ca_crt: fs::read(cred_bundle.ca_crt.as_path())
                    .with_context(|| format!("read {}", cred_bundle.ca_crt.display()))?,
            };
    
            Ok(serde_json::to_vec(&resource)?)

        } else {
            // Handle the case where the manager is None
            Err(anyhow!("Directory manager is uninitialized"))
        }
    }
}


/// Splitapi plugin
#[derive(Default, Debug)]
pub struct SplitapiPlugin {
    cp: CredentailProvisioner,
}

#[async_trait::async_trait]
impl Plugin for SplitapiPlugin {
    async fn get_name(&self) -> &str {
        PLUGIN_NAME
    }

    async fn get_resource(
        &self, 
        resource: &str, 
        query_string: &str
    ) -> Result<Vec<u8>> {
        log::info!("Query string: {}", query_string);

        let response: Vec<u8> = match resource {
            // plugin/nebula/credential?{query_string}
            // e.g. plugin/nebula/credential?ip[ip]=10.11.12.13&ip[netbits]=21&name=node1
            // the query_string will be used to generate the credential
            "credential" => {
                let params: SplitapiSandboxParams = serde_qs::from_str(query_string)?;
                self.cp.get_server_credential(&params)?
            }
            // resource not supported
            e => bail!("Nebula plugin resource {e} not supported"),
        };

        Ok(response)
    }
}