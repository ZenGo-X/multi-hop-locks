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

    #[test]
    fn test_setup() {
        let n: usize = 3;
        let amhl = MultiHopLock::setup(n);
        MultiHopLock::verify_setup(&amhl.setup_chain[0]).expect("error");
        MultiHopLock::verify_setup(&amhl.setup_chain[1]).expect("error");
    }
}
