#![allow(non_snake_case)]
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

extern crate curv;
extern crate itertools;
extern crate multi_party_ecdsa;

mod test;

use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{FE, GE};
use itertools::iterate;

pub struct MultiHopLock {
    pub num_parties: usize,
    pub y_0: FE,
    pub setup_chain: Vec<ChainLink>,
    pub setup_chain_link_u_n: ChainLinkUn,
}

pub struct ChainLink {
    pub Y_i_minus_1: GE,
    pub Y_i: GE,
    pub y_i: FE,
    pub proof: DLogProof,
}

pub struct ChainLinkUn {
    pub Y_i_minus_1: GE,
    pub k_n: FE,
}

impl MultiHopLock {
    pub fn setup(n: usize) -> MultiHopLock {
        let y_0: FE = ECScalar::new_random();
        let g: GE = ECPoint::generator();
        // let Y_0 = g * &y_0;
        let y_i_vec = (0..n).map(|_| ECScalar::new_random()).collect::<Vec<FE>>();

        let tuple_y_i_cumsum_index =
            iterate((y_0, 0 as usize), |y_i| (y_i.0 + y_i_vec[y_i.1], y_i.1 + 1))
                .take(n)
                .collect::<Vec<(FE, usize)>>();
        let y_i_cumsum = tuple_y_i_cumsum_index
            .iter()
            .map(|i| i.0)
            .collect::<Vec<FE>>();

        let tuple_Y_i_vec_proof_vec = (0..n)
            .map(|i| (g * y_i_cumsum[i], DLogProof::prove(&y_i_cumsum[i])))
            .collect::<Vec<(GE, DLogProof)>>();

        let chain_link_vec = (1..n)
            .map(|i| ChainLink {
                Y_i_minus_1: tuple_Y_i_vec_proof_vec[i - 1].0.clone(),
                Y_i: tuple_Y_i_vec_proof_vec[i].0.clone(),
                y_i: y_i_vec[i - 1].clone(),
                proof: tuple_Y_i_vec_proof_vec[i].1.clone(),
            })
            .collect::<Vec<ChainLink>>();
        let chain_link_u_n = ChainLinkUn {
            Y_i_minus_1: tuple_Y_i_vec_proof_vec[n - 1].0.clone(),
            k_n: y_i_cumsum[n - 1].clone(),
        };

        return MultiHopLock {
            num_parties: n,
            y_0,
            setup_chain: chain_link_vec,
            setup_chain_link_u_n: chain_link_u_n,
        };
    }

    pub fn verify_setup(chain_i: &ChainLink) -> Result<(), ()> {
        let verified = DLogProof::verify(&chain_i.proof);
        let g: GE = ECPoint::generator();
        let y_i_G = g * &chain_i.y_i;

        match verified {
            Err(_) => Err(()),
            Ok(_) => {
                if chain_i.proof.pk == chain_i.Y_i && y_i_G + chain_i.Y_i_minus_1 == chain_i.Y_i {
                    Ok(())
                } else {
                    Err(())
                }
            }
        }
    }
}
