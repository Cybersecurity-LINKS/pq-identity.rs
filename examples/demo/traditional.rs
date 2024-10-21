use std::{collections::HashMap, fs::File, path::Path};
use examples::{MemStorage, DID_URL, PATH_DID_FILE};
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::{core::{Duration, FromJson, Object, Timestamp, Url}, credential::{Credential, CredentialBuilder, DecodedJwtCredential, DecodedJwtPresentation, FailFast, Jwt, JwtCredentialValidationOptions, JwtCredentialValidator, JwtCredentialValidatorUtils, JwtPresentationOptions, JwtPresentationValidationOptions, JwtPresentationValidator, JwtPresentationValidatorUtils, Presentation, PresentationBuilder, Subject, SubjectHolderRelationship}, did::{CoreDID, DIDJwk, DID}, document::{verifiable::JwsVerificationOptions, CoreDocument}, resolver::Resolver, storage::{DidJwkDocumentExt, JwkMemStore, JwsSignatureOptions, KeyIdMemstore}, verification::{jws::JwsAlgorithm, MethodScope}};
use identity_iota::storage::JwkDocumentExt;
use reqwest::ClientBuilder;
use serde_json::json;
use colored::Colorize;

pub fn write_to_file(doc: &CoreDocument, path: Option<&str>) -> anyhow::Result<()> {
    let path = Path::new(path.unwrap_or_else(|| "did.json"));
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, doc)?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let binding = DID_URL.to_owned() + "did.json";
  let did_url: &str = binding.as_str();
  let binding = PATH_DID_FILE.to_owned() + "did.json";
  let path_did_file: &str = binding.as_str();

  println!("{} {} {}", "[Issuer]".red(), ": Create DID (with did:web method) and publish the DID Document at", did_url);

  let client= ClientBuilder::new()
  .danger_accept_invalid_certs(true)
  .build()?;

  let mut issuer_document: CoreDocument = CoreDocument::new_from_url(did_url)?;

  let storage_issuer: MemStorage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());
  let fragment_issuer = issuer_document.generate_method(
    &storage_issuer,
    JwkMemStore::ED25519_KEY_TYPE,
    JwsAlgorithm::EdDSA,
    None,
    MethodScope::VerificationMethod,
  ).await?;

  write_to_file(&issuer_document, Some(path_did_file))?;

  let storage_alice: MemStorage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());

  let (alice_document, fragment_alice) = CoreDocument::new_did_jwk(
    &storage_alice, 
    JwkMemStore::ED25519_KEY_TYPE, 
    JwsAlgorithm::EdDSA
  ).await?;

  println!("{} {} {}", "[Holder]".blue(), ": Create DID Jwk:", alice_document.id().as_str());

  let subject: Subject = Subject::from_json_value(json!({
    "id": alice_document.id().as_str(),
    "name": "Alice",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts",
    },
    "GPA": "4.0",
  }))?;

  println!("{} {} {}", "[Holder]".blue(), ": Inserted Credential subject information: ", serde_json::to_string_pretty(&subject)?);

  println!("{} {} {}", "[Holder]".blue(), " <-> [Issuer]".red(), ": Challenge-response protocol to authenticate Holder's DID");

  println!("{} {} ","[Issuer]".red(), ": Construct VC");
  
  let credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732")?)
    .issuer(Url::parse(issuer_document.id().as_str())?)
    .type_("UniversityDegreeCredential")
    .subject(subject)
    .build()?;

  let credential_jwt: Jwt = issuer_document.create_credential_jwt(
    &credential,
    &storage_issuer,
    &fragment_issuer,
    &JwsSignatureOptions::default(),
    None,
  ).await?;

  println!("{} {} {} {}", "[Issuer]".red(), " -> [Holder]".blue(), ": Sending VC (as JWT):", credential_jwt.as_str());

  println!("{} {} {}", "[Holder]".blue(), ": Resolve Issuer's DID:", issuer_document.id().as_str());

  println!("{} {}", "[Holder]".blue(), ": Validate VC");

  JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
  .validate::<_, Object>(
    &credential_jwt,
    &issuer_document,
    &JwtCredentialValidationOptions::default(),
    FailFast::FirstError,
  ).unwrap();

  println!("{} {}", "[Verifier]".green(),  "-> [Holder]: Send challenge");

  let challenge: &str = "475a7984-1bb5-4c4c-a56f-822bccd46440";

  let expires: Timestamp = Timestamp::now_utc().checked_add(Duration::minutes(10)).unwrap();

  println!("{} {}", "[Holder]".blue(), ": Construct VP");
  
  let presentation: Presentation<Jwt> =
    PresentationBuilder::new(alice_document.id().to_url().into(), Default::default())
      .credential(credential_jwt)
      .build()?;

  let presentation_jwt: Jwt = alice_document
    .create_presentation_jwt(
      &presentation,
      &storage_alice,
      &fragment_alice,
      &JwsSignatureOptions::default().nonce(challenge.to_owned()),
      &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await?;

  println!("{} {} {} {}", "[Holder]".blue(), " -> [Verifier]".green(),  ": Sending VP (as JWT):", presentation_jwt.as_str());

  // ===========================================================================
  // Step 7: Verifier receives the Verifiable Presentation and verifies it.
  // ===========================================================================

  // The verifier wants the following requirements to be satisfied:
  // - JWT verification of the presentation (including checking the requested challenge to mitigate replay attacks)
  // - JWT verification of the credentials.
  // - The presentation holder must always be the subject, regardless of the presence of the nonTransferable property
  // - The issuance date must not be in the future.

  println!("{}: Resolve Issuer's DID and verifies the Verifiable Presentation", "[Verifier]".green());

  let mut resolver: Resolver<CoreDocument> = Resolver::new();
  resolver.attach_did_jwk_handler();
  
  // Resolve the holder's document.
  let holder_did: DIDJwk = JwtPresentationValidatorUtils::extract_holder::<DIDJwk>(&presentation_jwt)?;
  let holder: CoreDocument = resolver.resolve(&holder_did).await?;

  let presentation_verifier_options: JwsVerificationOptions =
  JwsVerificationOptions::default().nonce(challenge.to_owned());

  // Validate presentation. Note that this doesn't validate the included credentials.
  let presentation_validation_options =
    JwtPresentationValidationOptions::default().presentation_verifier_options(presentation_verifier_options);
    
  let presentation: DecodedJwtPresentation<Jwt> = JwtPresentationValidator::with_signature_verifier(
    EdDSAJwsVerifier::default(),
  )
  .validate(&presentation_jwt, &holder, &presentation_validation_options)?;

  // Concurrently resolve the issuers' documents.
  let jwt_credentials: &Vec<Jwt> = &presentation.presentation.verifiable_credential;

  let mut resolver_web: Resolver<CoreDocument> = Resolver::new();
  let _ = resolver_web.attach_web_handler(client)?;

  let issuers: Vec<CoreDID> = jwt_credentials
    .iter()
    .map(JwtCredentialValidatorUtils::extract_issuer_from_jwt)
    .collect::<Result<Vec<CoreDID>, _>>()?;
  let issuers_documents: HashMap<CoreDID, CoreDocument> = resolver_web.resolve_multiple(&issuers).await?;

  // Validate the credentials in the presentation.
  let credential_validator: JwtCredentialValidator<EdDSAJwsVerifier> =
    JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default());
  let validation_options: JwtCredentialValidationOptions = JwtCredentialValidationOptions::default()
    .subject_holder_relationship(holder_did.to_url().into(), SubjectHolderRelationship::AlwaysSubject);

  for (index, jwt_vc) in jwt_credentials.iter().enumerate() {
    // SAFETY: Indexing should be fine since we extracted the DID from each credential and resolved it.
    let issuer_document: &CoreDocument = &issuers_documents[&issuers[index]];

    let _decoded_credential: DecodedJwtCredential<Object> = credential_validator
      .validate::<_, Object>(jwt_vc, issuer_document, &validation_options, FailFast::FirstError)
      .unwrap();
  }

  println!("{}: Verifiable Presentation successfully verified", "[Verifier]".green());

  Ok(())
}
