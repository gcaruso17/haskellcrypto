module Crypto where

import Data.Char

import Prelude hiding (gcd)

{-
The advantage of symmetric encryption schemes like AES is that they are efficient
and we can encrypt data of arbitrary size. The problem is how to share the key.
The flaw of the RSA is that it is slow and we can only encrypt data of size lower
than the RSA modulus n, usually around 1024 bits (64 bits for this exercise!).

We usually encrypt messages with a private encryption scheme like AES-256 with
a symmetric key k. The key k of fixed size 256 bits for example is then exchanged
via the aymmetric RSA.
-}

-------------------------------------------------------------------------------
-- PART 1 : asymmetric encryption

gcd :: Int -> Int -> Int
gcd m n
    | n == 0       = m
    | otherwise    = gcd n (m `mod` n)

phi :: Int -> Int
phi m
    = count range
      where
          count :: [Int] -> Int
          count []    = 0
          count (x : xs) = 1 + count xs
          range = [p | p <- [1..m], gcd p m == 1]

--
-- Calculates (u, v, d) the gcd (d) and Bezout coefficients (u and v)
-- such that au + bv = d
--
extendedGCD :: Int -> Int -> ((Int, Int), Int)
extendedGCD a 0           = ((1, 0), a)
extendedGCD a b           = ((v', u' - q * v'), gcd)
    where
        (q, r)            = quotRem a b
        ((u', v'), gcd)   = extendedGCD b r

-- Inverse of a modulo m
inverse :: Int -> Int -> Int
inverse a m                       = bcoefficient `mod` m
    where
        ((bcoefficient, _), _)    = extendedGCD a m

-- Calculates (a^k mod m)
--
modPow :: Int -> Int -> Int -> Int
modPow a k m
    | k == 0    = 1 `mod` m
    | even k    = modPow (a^2 `mod` m) (k `div` 2) m
    | otherwise = modPow a (k - 1) m * a `mod` m


-- Returns the smallest integer that is coprime with phi
smallestCoPrimeOf :: Int -> Int
-- Pre: a > 0
smallestCoPrimeOf a = head [b | b <- [2..], gcd a b == 1]

-- Generates keys pairs (public, private) = ((e, n), (d, n))
-- given two "large" distinct primes, p and q
genKeys :: Int -> Int -> ((Int, Int), (Int, Int))
genKeys p q = (publicKey, privateKey)
              where
                  publicKey     = (e, n)
                  privateKey    = (d, n)
                  n             = p * q
                  e             = smallestCoPrimeOf ((p - 1) * (q - 1))
                  d             = inverse e ((p - 1) * (q - 1))

-- RSA encryption/decryption; (e, n) is the public key
rsaEncrypt :: Int -> (Int, Int) -> Int
rsaEncrypt x (e, n) = modPow x e n

rsaDecrypt :: Int -> (Int, Int) -> Int
rsaDecrypt c (d, n) = modPow c d n


-------------------------------------------------------------------------------
-- PART 2 : symmetric encryption

-- Returns position of a letter in the alphabet
toInt :: Char -> Int
toInt a = ord a - ord 'a'

-- Returns the n^th letter
toChar :: Int -> Char
toChar n = chr (ord 'a' + n)

-- "adds" two letters
add :: Char -> Char -> Char
add a b = toChar ((aPos + bPos) `mod` modulo)
          where
              aPos      = toInt a
              bPos      = toInt b
              modulo    = toInt 'z' + 1

-- "substracts" two letters
substract :: Char -> Char -> Char
substract a b = toChar ((aPos - bPos) `mod` modulo)
          where
              aPos      = toInt a
              bPos      = toInt b
              modulo    = toInt 'z' + 1

-- the next functions present
-- 2 modes of operation for block ciphers : ECB and CBC
-- based on a symmetric encryption function e/d such as "add"

-- ecb (electronic codebook) with block size of a letter
--
ecbEncrypt :: Char -> String -> String
ecbEncrypt key "" = ""
ecbEncrypt key (x : xs)  = (add x key) : ecbEncrypt key xs

ecbDecrypt :: Char -> String -> String
ecbDecrypt key "" = ""
ecbDecrypt key (x : xs) = (substract x key) : ecbDecrypt key xs

-- cbc (cipherblock chaining) encryption with block size of a letter
-- initialisation vector iv is a letter
-- last argument is message m as a string
--
cbcEncrypt :: Char -> Char -> String -> String
cbcEncrypt key iv ""       = ""
cbcEncrypt key iv (x : xs) = c1 : cbcEncrypt key c1 xs
                             where
                                 c1    = (add (add x iv) key)

cbcDecrypt :: Char -> Char -> String -> String
cbcDecrypt key iv ""       = ""
cbcDecrypt key iv (c : cs) = x1 : cbcDecrypt key c cs
                             where
                                 x1    = ((substract c key) `substract` iv)
