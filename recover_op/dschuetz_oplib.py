#
# David Schuetz
# November 2018
#
# https://github.com/dschuetz/1password
#
# Library of functions called by all the other tools here.
#
# Not exactly a "clean" library -- many have debugging functions built
#   in that make them very noisy. And there are certainly inconsistencies
#   between functions regarding debug output, variable naming, calling 
#   conventions, style, and just general quality.
# 

import hashlib
import sys, base64, binascii, re

from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256

DEBUG = 1

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #  
#
# basic crypto stuff - wrappers around PyCryptoDome, etc.
#
# * encrypt/decrypt AES-GCM with 128-bit GCM tag
# * encrypt/decrypt AES-CBC with HMAC-SHA256 tag
# * encrypt/decrypt 1Password "opdata" structure 
#   * AES-CBC with HS-256 tag
#
# All use 256-bit keys
#
# Should probably pull RSA stuff out of the other scripts
# and add them here. 
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


#
# Decrypt CT with AES-GCM using key and iv
#   * If iv not provided, one will be created
#   * Verifies GCM tag 
#     - if verification fails, program will terminate with error
#   * Length of GCM tag hard-coded to 16 bytes
#
def dec_aes_gcm(ct, key, iv, tag):
    C = AES.new(key, AES.MODE_GCM, iv, mac_len=16)
    PT = C.decrypt_and_verify(ct, tag)
    return PT


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #  
#
# 1Password specific functionality
#
# * Compute 2SKD for generating MUK and SRP-X authenticator
# * Decrypt Windows EMK data
# * Generate and decode keys for local private vaults
#
# Some of these really don't ever get used except by a single
#   demonstration script. The line between a useful library
#   and just a convenient place to shove things is a little
#   blurry here. Whatever. :)
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#
# Implements the Two-Secret Key Derivation process (2SKD)
# Takes the user's:
#   * Secret Key (Account Key)
#   * Master Password
#   * Salt (p2salt)
#   * Iterations count (p2c)
#   * Algorithm (PBES2g-HS256, SRPg-4096)
#
# Returns the result (used for either MUK or SRP-X)
#
def compute_2skd(sk, password, email, p2salt, iterations, algorithm):
    p_debug("** Computing 2SKD\n")

    version = sk[0:2]
    account_id = sk[3:9]
    secret = re.sub('-', '', sk[10:])
    email = email.lower() # simple hack...not doing "proper" normalizaiton...

    email = str.encode(str(email))
    version = str.encode(str(version))

    secret = str.encode(str(secret))
    account_id = str.encode(str(account_id))

    algorithm = str.encode(str(algorithm))

    # p_str('Password', password)
    # p_str('Email', email)
    # p_str('Secret Key', sk)
    # p_str('   Version', version)
    # p_str('   AcctID', account_id)
    # p_str('   Secret', secret)
    # p_str('Algorithm', algorithm)
    # p_str('Iterations (p2c)', iterations)
    # p_str('Salt (p2s)', opb64e(p2salt))

    # p_data('Salt (decoded)', p2salt, dump=False)

    hkdf_pass_salt = HKDF(p2salt, 32, email, SHA256, 1, algorithm)

    # p_debug('\nHKDF(ikm=p2s, len=32, salt=email, hash=SHA256, count=1, info=algorithm)')
    # p_data('HKDF out: pass salt', hkdf_pass_salt, dump=False)

    password = str.encode(str(password))
    password_key = hashlib.pbkdf2_hmac('sha256', password, hkdf_pass_salt, iterations, dklen=32)

    # p_debug('\nPBKDF2(sha256, password, salt=HKDF_salt, iterations=p2c, 32 bytes)')
    # p_data('Derived password key', password_key, dump=False)

    # p_debug('\nHKDF(ikm=secret, len=32, salt=AcctID, hash=SHA256, count=1, info=version)')
    hkdf_key = HKDF(secret, 32, account_id, SHA256, 1, 'A3')
    # p_data('HKDF out: secret key', hkdf_key, dump=False)

    final_key = ''

    for x in range(0,32): 

        a = ord(password_key[x])
        b = ord(hkdf_key[x])
        c = a^b
        final_key = final_key + chr(c)

    # p_debug('\nXOR PBKDF2 output and SecretKey HKDF output')
    # p_data('Final 2SKD out', final_key, dump=False)

    return final_key

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #  
#
# basic debug / output stuff for consistent output
#
# most reformat the data into "<title>        <data>" format
# and then send to p_debug which decides whether or not to
# actually display the data
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#
# just prints the string, if DEBUG is true
#
def p_debug(out):
    if DEBUG:
        print out

#
# formats title and data into a left-justified 20-char
#   space for the title, then string
def p_str(title, data):
    dat_str = '%s' % data
    lines = dat_str.split('\n')

    p_debug('%-20s %s' % (title, lines[0]))
    for l in lines[1:]:
        p_debug('%20s %s' % ('', l))

#
# takes a hex string and formats an old-school DEBUG-like
#   dump of hex + ascii
#
def dump_line(dat):
    l_raw = binascii.a2b_hex(re.sub(' ', '', dat))
    asc = ''
    for c in l_raw:
        if ord(c) < 31 or ord(c) > 127:
            asc += '.'
        else:
            asc += c

    return('%-40s %s' % (dat, asc))


###############################################################
## TKTK - Need to fix this, drops singleton bytes from last line of hex dump
##   first re.sub seems to be the problem. just iterate and space.
###############################################################
def p_data(title, raw, decoded='', dump=True):
    print ""
    hex = re.sub(r'(....)', r'\1 ', binascii.b2a_hex(raw))
    hex_lines = re.sub(r'((.... ){1,8})', r'\1\n', hex).split('\n')

    if decoded != '' or dump == False:
        p_debug('%-20s %-40s  %s' % (title, hex_lines[0], decoded))
        for l in hex_lines[1:-1]:
            p_debug('%-20s %-40s' % ('', l))

    else:
        d_dat = dump_line(hex_lines[0])
        p_debug('%-20s %s' % (title, d_dat))
        for l in hex_lines[1:-1]:
            d_dat = dump_line(l)
            p_debug('%-20s %s' % ('', d_dat))


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #  
#
# Convenience functions for input/output
#
# * getbinary - prompt user for binary data (b64 or hex)
# * opb64d, opb64e - base64 decode with 1Password tricks
#    (URL safe altchars, not always including == padding, etc.)
# 
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


#
# The strings stored by 1Password don't always have padding characters at the
#   end. So we try multiple times until we get a good result.
#
# Also, 1Password uses url-safe encoding with - and _ replacing + and /.
#
def opb64d(b64dat):
    try:
        out = base64.b64decode(b64dat, altchars='-_')

    except:
        try:
            out = base64.b64decode(b64dat + '=', altchars='-_')

        except:
            try:
                out = base64.b64decode(b64dat + '==', altchars='-_')
            except:
                print "Problem b64 decoding string: %s" % (b64dat)
                sys.exit(1)

    return out

#
# Simple - encode something in base64 but use URL-safe
#   alt chars - and _ instead of + and /
#
def opb64e(dat):
    return base64.b64encode(dat, altchars='-_')