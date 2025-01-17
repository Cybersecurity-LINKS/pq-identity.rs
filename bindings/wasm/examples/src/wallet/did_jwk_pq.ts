// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

import {
    JwkMemStore,
    JwsAlgorithm,
    KeyIdMemStore,
    Storage,
    CoreDocument
} from "@iota/identity-wasm/node";

/** Demonstrate how to create a DID JWK PQ Document */
export async function createDidJwkPq(){

    const storage: Storage = new Storage(new JwkMemStore(), new KeyIdMemStore());
    const document = await CoreDocument.newDidJwkPq(
        storage,
        JwkMemStore.mldsaKeyType(),
        JwsAlgorithm.MLDSA44)

    console.log(JSON.stringify(document, null, 2));
}