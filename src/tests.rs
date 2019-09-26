/*
    sin-city

    Copyright 2018 by Kzen Networks

    This file is part of paradise-city library
    (https://github.com/KZen-networks/sin-city)

    sin-city is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/sin-city/blob/master/LICENSE>
*/
#[cfg(test)]
mod tests {

    use MultiHopLock;

    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;

    #[test]
    fn test_setup() {
        let n: usize = 3;
        let amhl = MultiHopLock::setup(n);
        MultiHopLock::verify_setup(&amhl.setup_chain[0]).expect("error");
        MultiHopLock::verify_setup(&amhl.setup_chain[1]).expect("error");
    }

    use curv::arithmetic::traits::Samplable;
    use curv::elliptic::curves::traits::ECScalar;
    use curv::{BigInt, FE};
    use get_paillier_keys;
    use LockParty0Message1;
    use LockParty0Message2;
    use LockParty1Message1;
    use LockParty1Message2;

    #[test]
    fn test_lock() {
        // 2p-keygen
        // party0 in Lock protocol plays party_one . party1 in Lock protocol plays party_two
        let random_third = BigInt::sample_below(&(FE::q() / BigInt::from(3)));
        let secret_share_party_one: FE = ECScalar::from(&random_third);
        let (party_one_first_message, comm_witness, ec_key_pair_party1) =
            party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(
                secret_share_party_one.clone(),
            );

        let secret_share_party_two: FE = ECScalar::new_random();
        let (party_two_first_message, ec_key_pair_party2) =
            party_two::KeyGenFirstMsg::create_with_fixed_secret_share(
                secret_share_party_two.clone(),
            );
        let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
            comm_witness,
            &party_two_first_message.d_log_proof,
        )
        .expect("failed to verify and decommit");

        let _party_two_second_message =
            party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message,
            )
            .expect("failed to verify commitments and DLog proof");

        // init paillier keypair:
        let (ek, dk) = get_paillier_keys();
        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_encrypted_share_from_fixed_paillier_keypair(
                &ek,
                &dk,
                &ec_key_pair_party1,
            );

        let party_one_private =
            party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

        let party_two_paillier = party_two::PaillierPublic {
            ek: paillier_key_pair.ek.clone(),
            encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
        };

        let correct_key_proof =
            party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);
        party_two::PaillierPublic::verify_ni_proof_correct_key(
            correct_key_proof,
            &party_two_paillier.ek,
        )
        .expect("bad paillier key");
        // zk proof of correct paillier key

        // zk range proof
        let range_proof = party_one::PaillierKeyPair::generate_range_proof(
            &paillier_key_pair,
            &party_one_private,
        );
        let _result =
            party_two::PaillierPublic::verify_range_proof(&party_two_paillier, &range_proof)
                .expect("range proof error");

        // pdl proof minus range proof
        let (party_two_pdl_first_message, pdl_chal_party2) =
            party_two_paillier.pdl_challenge(&party_one_second_message.comm_witness.public_share);

        let (party_one_pdl_first_message, pdl_decommit_party1, alpha) =
            party_one::PaillierKeyPair::pdl_first_stage(
                &party_one_private,
                &party_two_pdl_first_message,
            );

        let party_two_pdl_second_message =
            party_two::PaillierPublic::pdl_decommit_c_tag_tag(&pdl_chal_party2);
        let party_one_pdl_second_message = party_one::PaillierKeyPair::pdl_second_stage(
            &party_two_pdl_first_message,
            &party_two_pdl_second_message,
            party_one_private.clone(),
            pdl_decommit_party1,
            alpha,
        )
        .expect("pdl error party2");

        party_two::PaillierPublic::verify_pdl(
            &pdl_chal_party2,
            &party_one_pdl_first_message,
            &party_one_pdl_second_message,
        )
        .expect("pdl error party1");

        //compute public key party_one:
        let pubkey_party_one =
            party_one::compute_pubkey(&party_one_private, &party_two_first_message.public_share);

        //compute public key party_two:
        let pubkey_party_two = party_two::compute_pubkey(
            &ec_key_pair_party2,
            &party_one_second_message.comm_witness.public_share,
        );

        assert_eq!(pubkey_party_one, pubkey_party_two);
        // instead of using the original Lindell ephemeral key generation we will use amhl version:
        let n: usize = 3;
        let amhl = MultiHopLock::setup(n);

        let (r_1, decommit, lock_party1_message1) =
            LockParty1Message1::first_message(&amhl.setup_chain[1].Y_i_minus_1);

        let (r_0, lock_party0_message1) =
            LockParty0Message1::first_message(&amhl.setup_chain[0].Y_i);

        let message = BigInt::from(2); //TODO: what is the message ?

        let lock_party1_message2 = LockParty1Message2::second_message(
            &lock_party0_message1,
            decommit,
            &party_two_paillier.ek,
            &secret_share_party_two,
            &party_two_paillier.encrypted_secret_share,
            &message,
            &r_1,
            &amhl.setup_chain[1].Y_i_minus_1,
        );

        let (_s_tag_party0, lock_party0_message2) = LockParty0Message2::second_message(
            &dk,
            lock_party1_message2,
            lock_party1_message1,
            &message,
            r_0,
            &amhl.setup_chain[0].Y_i,
            &pubkey_party_one,
        );

        // party1_output:
        let (_s_tag_party1, _r_x) =
            lock_party0_message2.verify(lock_party0_message1, &r_1, &pubkey_party_two, &message);
    }

    use Release;
    use SL;
    use SR;

    #[test]
    fn test_release() {
        let n: usize = 5;
        let amhl = MultiHopLock::setup(n);
        MultiHopLock::verify_setup(&amhl.setup_chain[0]).expect("error");
        MultiHopLock::verify_setup(&amhl.setup_chain[1]).expect("error");
        MultiHopLock::verify_setup(&amhl.setup_chain[2]).expect("error");
        MultiHopLock::verify_setup(&amhl.setup_chain[3]).expect("error");
        // U4 cannot be verified

        ////////////// lock 1: (keygen is used without the zk proofs to make the test shorter) ////////////
        // party0 in Lock protocol plays party_one . party1 in Lock protocol plays party_two
        let random_third = BigInt::sample_below(&(FE::q() / BigInt::from(3)));
        let secret_share_party_one: FE = ECScalar::from(&random_third);
        let (party_one_first_message, comm_witness, ec_key_pair_party1) =
            party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(
                secret_share_party_one.clone(),
            );

        let secret_share_party_two: FE = ECScalar::new_random();
        let (party_two_first_message, ec_key_pair_party2) =
            party_two::KeyGenFirstMsg::create_with_fixed_secret_share(
                secret_share_party_two.clone(),
            );
        let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
            comm_witness,
            &party_two_first_message.d_log_proof,
        )
        .expect("failed to verify and decommit");

        let _party_two_second_message =
            party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message,
            )
            .expect("failed to verify commitments and DLog proof");

        // init paillier keypair:
        let (ek, dk) = get_paillier_keys();
        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_encrypted_share_from_fixed_paillier_keypair(
                &ek,
                &dk,
                &ec_key_pair_party1,
            );

        let party_one_private =
            party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

        let party_two_paillier = party_two::PaillierPublic {
            ek: paillier_key_pair.ek.clone(),
            encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
        };

        //compute public key party_one:
        let pubkey_party_one =
            party_one::compute_pubkey(&party_one_private, &party_two_first_message.public_share);

        //compute public key party_two:
        let pubkey_party_two = party_two::compute_pubkey(
            &ec_key_pair_party2,
            &party_one_second_message.comm_witness.public_share,
        );

        let (r_1, decommit, lock_party1_message1) =
            LockParty1Message1::first_message(&amhl.setup_chain[1].Y_i_minus_1);

        let (r_0, lock_party0_message1) =
            LockParty0Message1::first_message(&amhl.setup_chain[0].Y_i);

        let message = BigInt::from(2);

        let lock_party1_message2 = LockParty1Message2::second_message(
            &lock_party0_message1,
            decommit,
            &party_two_paillier.ek,
            &secret_share_party_two,
            &party_two_paillier.encrypted_secret_share,
            &message,
            &r_1,
            &amhl.setup_chain[1].Y_i_minus_1,
        );

        let (s_tag_party0, lock_party0_message2) = LockParty0Message2::second_message(
            &dk,
            lock_party1_message2,
            lock_party1_message1,
            &message,
            r_0,
            &amhl.setup_chain[0].Y_i,
            &pubkey_party_one,
        );

        // party1_output:
        let (s_tag_party1, r_x) =
            lock_party0_message2.verify(lock_party0_message1, &r_1, &pubkey_party_two, &message);

        let _s_0_R = SR {
            message: ECScalar::from(&message),
            s_tag: s_tag_party0,
        };
        let s_1_L = SL {
            w_0: r_x,
            w_1: s_tag_party1,
            pk: pubkey_party_two,
        };

        ////////////// lock2: ////////////
        let random_third = BigInt::sample_below(&(FE::q() / BigInt::from(3)));
        let secret_share_party_one: FE = ECScalar::from(&random_third);
        let (party_one_first_message, comm_witness, ec_key_pair_party1) =
            party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(
                secret_share_party_one.clone(),
            );

        let secret_share_party_two: FE = ECScalar::new_random();
        let (party_two_first_message, ec_key_pair_party2) =
            party_two::KeyGenFirstMsg::create_with_fixed_secret_share(
                secret_share_party_two.clone(),
            );
        let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
            comm_witness,
            &party_two_first_message.d_log_proof,
        )
        .expect("failed to verify and decommit");

        let _party_two_second_message =
            party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message,
            )
            .expect("failed to verify commitments and DLog proof");

        // init paillier keypair:
        let (ek, dk) = get_paillier_keys();
        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_encrypted_share_from_fixed_paillier_keypair(
                &ek,
                &dk,
                &ec_key_pair_party1,
            );

        let party_one_private =
            party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

        let party_two_paillier = party_two::PaillierPublic {
            ek: paillier_key_pair.ek.clone(),
            encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
        };

        //compute public key party_one:
        let pubkey_party_one =
            party_one::compute_pubkey(&party_one_private, &party_two_first_message.public_share);

        //compute public key party_two:
        let pubkey_party_two = party_two::compute_pubkey(
            &ec_key_pair_party2,
            &party_one_second_message.comm_witness.public_share,
        );

        let (r_1, decommit, lock_party1_message1) =
            LockParty1Message1::first_message(&amhl.setup_chain[2].Y_i_minus_1);

        let (r_0, lock_party0_message1) =
            LockParty0Message1::first_message(&amhl.setup_chain[1].Y_i);

        let message = BigInt::from(2);

        let lock_party1_message2 = LockParty1Message2::second_message(
            &lock_party0_message1,
            decommit,
            &party_two_paillier.ek,
            &secret_share_party_two,
            &party_two_paillier.encrypted_secret_share,
            &message,
            &r_1,
            &amhl.setup_chain[2].Y_i_minus_1,
        );

        let (s_tag_party0, lock_party0_message2) = LockParty0Message2::second_message(
            &dk,
            lock_party1_message2,
            lock_party1_message1,
            &message,
            r_0,
            &amhl.setup_chain[1].Y_i,
            &pubkey_party_one,
        );

        // party1_output:
        let (s_tag_party1, r_x) =
            lock_party0_message2.verify(lock_party0_message1, &r_1, &pubkey_party_two, &message);

        let s_1_R = SR {
            message: ECScalar::from(&message),
            s_tag: s_tag_party0,
        };
        let s_2_L = SL {
            w_0: r_x,
            w_1: s_tag_party1,
            pk: pubkey_party_two,
        };

        ////////////// lock3: ////////////
        let random_third = BigInt::sample_below(&(FE::q() / BigInt::from(3)));
        let secret_share_party_one: FE = ECScalar::from(&random_third);
        let (party_one_first_message, comm_witness, ec_key_pair_party1) =
            party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(
                secret_share_party_one.clone(),
            );

        let secret_share_party_two: FE = ECScalar::new_random();
        let (party_two_first_message, ec_key_pair_party2) =
            party_two::KeyGenFirstMsg::create_with_fixed_secret_share(
                secret_share_party_two.clone(),
            );
        let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
            comm_witness,
            &party_two_first_message.d_log_proof,
        )
        .expect("failed to verify and decommit");

        let _party_two_second_message =
            party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message,
            )
            .expect("failed to verify commitments and DLog proof");

        // init paillier keypair:
        let (ek, dk) = get_paillier_keys();
        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_encrypted_share_from_fixed_paillier_keypair(
                &ek,
                &dk,
                &ec_key_pair_party1,
            );

        let party_one_private =
            party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

        let party_two_paillier = party_two::PaillierPublic {
            ek: paillier_key_pair.ek.clone(),
            encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
        };

        //compute public key party_one:
        let pubkey_party_one =
            party_one::compute_pubkey(&party_one_private, &party_two_first_message.public_share);

        //compute public key party_two:
        let pubkey_party_two = party_two::compute_pubkey(
            &ec_key_pair_party2,
            &party_one_second_message.comm_witness.public_share,
        );

        let (r_1, decommit, lock_party1_message1) =
            LockParty1Message1::first_message(&amhl.setup_chain[3].Y_i_minus_1);

        let (r_0, lock_party0_message1) =
            LockParty0Message1::first_message(&amhl.setup_chain[2].Y_i);

        let message = BigInt::from(2);

        let lock_party1_message2 = LockParty1Message2::second_message(
            &lock_party0_message1,
            decommit,
            &party_two_paillier.ek,
            &secret_share_party_two,
            &party_two_paillier.encrypted_secret_share,
            &message,
            &r_1,
            &amhl.setup_chain[3].Y_i_minus_1,
        );

        let (s_tag_party0, lock_party0_message2) = LockParty0Message2::second_message(
            &dk,
            lock_party1_message2,
            lock_party1_message1,
            &message,
            r_0,
            &amhl.setup_chain[2].Y_i,
            &pubkey_party_one,
        );

        // party1_output:
        let (s_tag_party1, r_x) =
            lock_party0_message2.verify(lock_party0_message1, &r_1, &pubkey_party_two, &message);

        let s_2_R = SR {
            message: ECScalar::from(&message),
            s_tag: s_tag_party0,
        };
        let s_3_L = SL {
            w_0: r_x,
            w_1: s_tag_party1,
            pk: pubkey_party_two,
        };

        ////////////// lock4: ////////////
        let random_third = BigInt::sample_below(&(FE::q() / BigInt::from(3)));
        let secret_share_party_one: FE = ECScalar::from(&random_third);
        let (party_one_first_message, comm_witness, ec_key_pair_party1) =
            party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(
                secret_share_party_one.clone(),
            );

        let secret_share_party_two: FE = ECScalar::new_random();
        let (party_two_first_message, ec_key_pair_party2) =
            party_two::KeyGenFirstMsg::create_with_fixed_secret_share(
                secret_share_party_two.clone(),
            );
        let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
            comm_witness,
            &party_two_first_message.d_log_proof,
        )
        .expect("failed to verify and decommit");

        let _party_two_second_message =
            party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message,
            )
            .expect("failed to verify commitments and DLog proof");

        // init paillier keypair:
        let (ek, dk) = get_paillier_keys();
        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_encrypted_share_from_fixed_paillier_keypair(
                &ek,
                &dk,
                &ec_key_pair_party1,
            );

        let party_one_private =
            party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

        let party_two_paillier = party_two::PaillierPublic {
            ek: paillier_key_pair.ek.clone(),
            encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
        };

        //compute public key party_one:
        let pubkey_party_one =
            party_one::compute_pubkey(&party_one_private, &party_two_first_message.public_share);

        //compute public key party_two:
        let pubkey_party_two = party_two::compute_pubkey(
            &ec_key_pair_party2,
            &party_one_second_message.comm_witness.public_share,
        );

        let (r_1, decommit, lock_party1_message1) =
            LockParty1Message1::first_message(&amhl.setup_chain_link_u_n.Y_i_minus_1);

        let (r_0, lock_party0_message1) =
            LockParty0Message1::first_message(&amhl.setup_chain[3].Y_i);

        let message = BigInt::from(2);

        let lock_party1_message2 = LockParty1Message2::second_message(
            &lock_party0_message1,
            decommit,
            &party_two_paillier.ek,
            &secret_share_party_two,
            &party_two_paillier.encrypted_secret_share,
            &message,
            &r_1,
            &amhl.setup_chain_link_u_n.Y_i_minus_1,
        );

        let (s_tag_party0, lock_party0_message2) = LockParty0Message2::second_message(
            &dk,
            lock_party1_message2,
            lock_party1_message1,
            &message,
            r_0,
            &amhl.setup_chain[3].Y_i,
            &pubkey_party_one,
        );

        // party1_output:
        let (s_tag_party1, r_x) =
            lock_party0_message2.verify(lock_party0_message1, &r_1, &pubkey_party_two, &message);

        let s_3_R = SR {
            message: ECScalar::from(&message),
            s_tag: s_tag_party0,
        };
        let s_4_L = SL {
            w_0: r_x,
            w_1: s_tag_party1,
            pk: pubkey_party_two,
        };
        //////////// release lock 4: party U4 sends s_L_4 to party U3 ////////////
        //////////// release lock 3: ////////////
        let k_2 = Release::release_n_minus_1(
            &amhl.setup_chain[3],
            &amhl.setup_chain_link_u_n,
            &s_4_L,
            &s_3_L,
            &s_3_R,
        )
        .expect("error lock 3");
        ////////////// release lock 2 ////////////
        let k_1 =
            Release::release_i(&amhl.setup_chain[2], k_2, &s_2_L, &s_2_R).expect("error lock 2");
        ////////////// release lock 1: ////////////
        let _k_0 =
            Release::release_i(&amhl.setup_chain[1], k_1, &s_1_L, &s_1_R).expect("error lock 2");
    }

}
