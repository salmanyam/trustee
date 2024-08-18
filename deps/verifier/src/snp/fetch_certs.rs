extern crate serde;
use super::*;
use core::fmt;
use std::str::FromStr;

use openssl::x509::X509;

use crate::snp::VendorCertificates;
use sev::firmware::guest::AttestationReport;

use reqwest::blocking::{get, Response};
use reqwest::StatusCode;
use std::result::Result::Ok;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endorsement {
    /// Versioned Chip Endorsement Key
    Vcek,

    /// Versioned Loaded Endorsement Key
    Vlek,
}

impl fmt::Display for Endorsement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endorsement::Vcek => write!(f, "VCEK"),
            Endorsement::Vlek => write!(f, "VLEK"),
        }
    }
}

impl FromStr for Endorsement {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "vcek" => Ok(Self::Vcek),
            "vlek" => Ok(Self::Vlek),
            _ => Err(anyhow::anyhow!("Endorsement type not found!")),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProcType {
    /// 3rd Gen AMD EPYC Processor (Standard)
    Milan,

    /// 4th Gen AMD EPYC Processor (Standard)
    Genoa,

    /// 4th Gen AMD EPYC Processor (Performance)
    Bergamo,

    /// 4th Gen AMD EPYC Processor (Edge)
    Siena,
}

impl ProcType {
    fn to_kds_url(&self) -> String {
        match self {
            ProcType::Genoa | ProcType::Siena | ProcType::Bergamo => &ProcType::Genoa,
            _ => self,
        }
        .to_string()
    }
}

impl FromStr for ProcType {
    type Err = anyhow::Error;
    fn from_str(input: &str) -> Result<ProcType, anyhow::Error> {
        match input.to_lowercase().as_str() {
            "milan" => Ok(ProcType::Milan),
            "genoa" => Ok(ProcType::Genoa),
            "bergamo" => Ok(ProcType::Bergamo),
            "siena" => Ok(ProcType::Siena),
            _ => Err(anyhow::anyhow!("Processor type not found!")),
        }
    }
}

impl fmt::Display for ProcType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProcType::Milan => write!(f, "Milan"),
            ProcType::Genoa => write!(f, "Genoa"),
            ProcType::Bergamo => write!(f, "Bergamo"),
            ProcType::Siena => write!(f, "Siena"),
        }
    }
}

// Function to build kds request for ca chain and return a vector with the 2 certs (ASK & ARK)
pub(crate) fn request_ca_kds(
    processor_model: ProcType,
    endorser: &Endorsement,
) -> Result<Vec<X509>, anyhow::Error> {
    const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
    const KDS_CERT_CHAIN: &str = "cert_chain";

    // Should make -> https://kdsintf.amd.com/vcek/v1/{SEV_PROD_NAME}/cert_chain
    let url: String = format!(
        "{KDS_CERT_SITE}/{}/v1/{}/{KDS_CERT_CHAIN}",
        endorser.to_string().to_lowercase(),
        processor_model.to_kds_url()
    );

    let rsp: Response = get(url).context("Unable to send request for certs to URL")?;

    match rsp.status() {
        StatusCode::OK => {
            // Parse the request
            let body = rsp
                .bytes()
                .context("Unable to parse AMD certificate chain")?
                .to_vec();

            let certificates = X509::stack_from_pem(&body)?;

            Ok(certificates)
        }
        status => Err(anyhow::anyhow!("Unable to fetch certificate: {:?}", status)),
    }
}

// Function to request vcek from KDS. Return vcek in der format.
pub(crate) fn request_vcek_kds(
    processor_model: ProcType,
    att_report: &AttestationReport,
) -> Result<Vec<u8>, anyhow::Error> {
    // KDS URL parameters
    const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
    const KDS_VCEK: &str = "/vcek/v1";

    // Use attestation report to get data for URL
    let hw_id: String = hex::encode(att_report.chip_id);

    let vcek_url: String = format!(
        "{KDS_CERT_SITE}{KDS_VCEK}/{}/\
            {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        processor_model.to_kds_url(),
        att_report.reported_tcb.bootloader,
        att_report.reported_tcb.tee,
        att_report.reported_tcb.snp,
        att_report.reported_tcb.microcode
    );
    println!("vcek url = {}", vcek_url);

    // VCEK in DER format
    let vcek_rsp: Response = get(vcek_url).context("Unable to send request for VCEK")?;

    match vcek_rsp.status() {
        StatusCode::OK => {
            let vcek_rsp_bytes: Vec<u8> =
                vcek_rsp.bytes().context("Unable to parse VCEK")?.to_vec();
            Ok(vcek_rsp_bytes)
        }
        status => Err(anyhow::anyhow!("Unable to fetch VCEK from URL: {status:?}")),
    }
}

//TCB bl = 7
//TCB tee = 0
//TCB snp = 11
//TCB mc = 62

fn is_genoa_tcb(att_report: &AttestationReport) -> bool {
    att_report.current_tcb.bootloader == 7
        && att_report.current_tcb.tee == 0
        && att_report.current_tcb.snp == 11
        && att_report.current_tcb.microcode == 62
}

pub(crate) fn fetch_cert_chain(att_report: &AttestationReport) -> Result<VendorCertificates> {
    // check the processor verison from the att report

    println!("TCB bl = {}", att_report.current_tcb.bootloader);
    println!("TCB tee = {}", att_report.current_tcb.tee);
    println!("TCB snp = {}", att_report.current_tcb.snp);
    println!("TCB mc = {}", att_report.current_tcb.microcode);

    println!("Is Genoa = {}", is_genoa_tcb(&att_report));

    // Get certs from kds
    let processor_type = ProcType::from_str("Genoa")?;
    let endorsement_type = Endorsement::from_str("vcek")?;

    let certificates = request_ca_kds(processor_type.clone(), &endorsement_type)?;

    let ark = &certificates[1];
    let ask = &certificates[0];

    //let ark_pem_bytes: Vec<u8> = ark.to_pem().expect("Failed to convert ARK from X509 to PEM");
    //let ask_pem_bytes: Vec<u8> = ask.to_pem().expect("Failed to convert ASK from X509 to PEM");

    //let ark_byte_slice: &[u8] = &ark_pem_bytes;
    //let ask_byte_slice: &[u8] = &ask_pem_bytes;

    //let ark_cert = Certificate::from_bytes(&ark_byte_slice)?;
    //let ask_cert = Certificate::from_bytes(&ask_byte_slice)?;

    // Request vcek
    let vcek_pem_bytes = request_vcek_kds(processor_type, &att_report)?;

    // Parse the raw certificate bytes into an X509 object
    let vcek_cert = X509::from_der(&vcek_pem_bytes).unwrap();

    //let vcek_byte_slice: &[u8] = &vcek_pem_bytes;
    //let vcek_cert = Certificate::from_bytes(&vcek_byte_slice)?;

    let vendor_certs = VendorCertificates {
        ask: ask.clone(),
        ark: ark.clone(),
        asvk: vcek_cert.clone(),
    };
    Ok(vendor_certs)
}
