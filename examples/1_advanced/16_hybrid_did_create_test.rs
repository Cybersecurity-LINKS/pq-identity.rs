
use std::collections::HashMap;
use std::mem;

use examples::*;
use examples::MemStorage;
use identity_iota::core::Duration;
use identity_iota::core::FromJson;
use identity_iota::core::Object;
use identity_iota::core::Timestamp;
use identity_iota::core::ToJson;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::DecodedJwtPresentation;
use identity_iota::credential::FailFast;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::JwtPresentationValidationOptions;
use identity_iota::credential::JwtPresentationValidator;
use identity_iota::credential::JwtPresentationValidatorUtils;
use identity_iota::credential::Presentation;
use identity_iota::credential::PresentationBuilder;
use identity_iota::credential::Subject;
use identity_iota::credential::SubjectHolderRelationship;
use identity_iota::did::CoreDID;
use identity_iota::did::DID;
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::iota::IotaClientExt;
use identity_iota::iota::IotaDocument;
use identity_iota::iota::IotaIdentityClientExt;
use identity_iota::iota::NetworkName;
use identity_iota::resolver::Resolver;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwkDocumentExtHybrid;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::JwpDocumentExt;
use identity_iota::storage::JwsDocumentExtPQC;
use identity_iota::storage::JwsSignatureOptions;
use identity_iota::storage::KeyIdMemstore;
use identity_iota::storage::KeyType;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::CompositeAlgId;
use identity_iota::verification::MethodScope;
use identity_pqc_verifier::PQCJwsVerifier;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::secret::SecretManager;
use iota_sdk::client::Client;
use iota_sdk::client::Password;
use iota_sdk::types::block::address::Address;
use iota_sdk::types::block::output::AliasOutput;
use jsonprooftoken::jpa::algs::ProofAlgorithm;
use serde_json::json;
use tokio::time::Instant;
use tokio::try_join;

// The API endpoint of an IOTA node, e.g. Hornet.
const API_ENDPOINT: &str = "http://192.168.94.191";
// const API_ENDPOINT: &str = "https://api.testnet.shimmer.network";
// The faucet endpoint allows requesting funds for testing purposes.
const FAUCET_ENDPOINT: &str = "http://faucet.testnet.shimmer.network/api/enqueue";

// // The API endpoint of an IOTA node, e.g. Hornet.
// const API_ENDPOINT: &str = "http://localhost";
// // The faucet endpoint allows requesting funds for testing purposes.
// const FAUCET_ENDPOINT: &str = "http://localhost/faucet/api/enqueue";


async fn create_did(client: &Client, address: Address, network_name: &NetworkName, secret_manager: &SecretManager, storage: &MemStorage, alg_id: CompositeAlgId) -> anyhow::Result<(Address, IotaDocument, String)> {
  let start_time = Instant::now();
  
  // Create a new DID document with a placeholder DID.
  // The DID will be derived from the Alias Id of the Alias Output after publishing.
  let mut document: IotaDocument = IotaDocument::new(&network_name);

  // New Verification Method containing a PQC key
  let fragment = 
    document.generate_method_hybrid(
        &storage, 
        alg_id, 
        None, 
        MethodScope::VerificationMethod
    ).await.unwrap();

  // Construct an Alias Output containing the DID document, with the wallet address
  // set as both the state controller and governor.
  let alias_output: AliasOutput = client.new_did_output(address, document, None).await?;

  // Publish the Alias Output and get the published DID document.
  let document: IotaDocument = client.publish_did_output(&secret_manager, alias_output).await?;

  let elapsed_time = start_time.elapsed();

  println!("Time elapsed: {} ms", elapsed_time.as_millis());

  Ok((address, document, fragment))
}



// async fn create_did_zk(client: &Client, address: Address, network_name: &NetworkName, secret_manager: &SecretManager, storage: &MemStorage, key_type: KeyType, alg: ProofAlgorithm) -> anyhow::Result<(Address, IotaDocument, String)> {

//   let start_time = Instant::now();
  
//   // Create a new DID document with a placeholder DID.
//   // The DID will be derived from the Alias Id of the Alias Output after publishing.
//   let mut document: IotaDocument = IotaDocument::new(&network_name);

//   // New Verification Method containing a PQC key
//   let fragment = if alg == JwsAlgorithm::EdDSA && key_type == JwkMemStore::ED25519_KEY_TYPE {
  
//     document.generate_method_jwp(
//         &storage, 
//         key_type, 
//         alg, 
//         None, 
//         MethodScope::VerificationMethod
//     ).await.unwrap()

//   } else {
//     document.generate_method_pqc(
//         &storage, 
//         key_type, 
//         alg, 
//         None, 
//         MethodScope::VerificationMethod
//     ).await.unwrap()

//   };

//   // Construct an Alias Output containing the DID document, with the wallet address
//   // set as both the state controller and governor.
//   let alias_output: AliasOutput = client.new_did_output(address, document, None).await?;

//   // Publish the Alias Output and get the published DID document.
//   let document: IotaDocument = client.publish_did_output(&secret_manager, alias_output).await?;

//   let elapsed_time = start_time.elapsed();

//   println!("Time elapsed: {} ms", elapsed_time.as_millis());

//   Ok((address, document, fragment))
// }


/// Demonstrates how to create a Post-Quantum Verifiable Credential.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // ===========================================================================
  // Step 1: Create identitiy for the issuer.
  // ===========================================================================

  // Create a new client to interact with the IOTA ledger.
  let client: Client = Client::builder()
    .with_primary_node(API_ENDPOINT, None)?
    .finish()
    .await?;


  let secret_manager_issuer = SecretManager::Stronghold(StrongholdSecretManager::builder()
  .password(Password::from("secure_password_1".to_owned()))
  .build(random_stronghold_path())?);

  let storage_issuer: MemStorage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());

  // Get an address with funds for testing.
  let address: Address = get_address_with_funds(&client, &secret_manager_issuer, FAUCET_ENDPOINT).await?;

  // Get the Bech32 human-readable part (HRP) of the network.
  let network_name: NetworkName = client.network_name().await?;

  let n = 1;
  let printing = true;

  println!("IdMldsa44Ed25519Sha512\n");
  for _ in 0..n {
    let (_, doc, _) = create_did(&client, address, &network_name, &secret_manager_issuer, &storage_issuer, CompositeAlgId::IdMldsa44Ed25519Sha512).await?;
    if printing {
      let a = doc.to_json_vec()?;
      println!("{}", a.len());
    }
  }

  println!("IdMldsa65Ed25519Sha512\n");
  for _ in 0..n {
    let (_, doc, _) = create_did(&client, address, &network_name, &secret_manager_issuer, &storage_issuer, CompositeAlgId::IdMldsa65Ed25519Sha512).await?;
    if printing {
      let a = doc.to_json_vec()?;
      println!("{}", a.len());
    }
  }

  Ok(())
}