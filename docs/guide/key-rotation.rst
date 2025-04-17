:description: Simple example of key rotation using ``joserfc``

Key Rotation
============

``joserfc`` provides functionality to help implement key rotation in your
application.

Disabling keys
--------------

``BaseKey`` has a ``jrfc_disabled`` property which, if set to ``True``, will
prevent the key from being selected by ``KeySet.pick_random_key`` and used for
encrypting or signing tokens. It may still be used for decrypting or verifying
tokens. This allows keys to be removed from the ``KeySet`` safely; once a key
has been disabled on every host that creates tokens for the lifetime of your
tokens, it may be removed from the ``KeySet``.

.. code-block:: python

    import json

    with open("your-jwks.json") as f:
        data = json.load(f)
        key_set = KeySet.import_key_set(data)

    oldest_key = sorted(key_set, key=lambda k: k.get("jrfc_created_at"))[0]
    oldest_key.jrfc_disabled = True


Managing KeySets
----------------

Below is a simple command line program that can create keysets and perform
key rotation.

.. code-block:: python

    # manage-keyset.py
    import argparse
    import json
    import sys
    import time
    from enum import StrEnum, auto

    from joserfc import jwk

    class Command(StrEnum):
        GENERATE = auto()
        ADD = auto()
        REMOVE = auto()

    parser = argparse.ArgumentParser()
    parser.add_argument("command", type=str, choices=[c.value for c in Command])
    parser.add_argument("keyset_file", type=str)
    parser.add_argument("--kid", type=str)
    parser.add_argument("--remove-oldest", action="store_true")
    parser.add_argument("--disable", action="store_true", help="Disable keys instead of removing them")

    args = parser.parse_args()
    args._print_help = parser.print_help

    def write_keyset(keyset: jwk.KeySet, keyset_file: str):
        with open(keyset_file, "wt") as f:
            json.dump(keyset.as_dict(), f)

    def read_keyset(keyset_file: str) -> jwk.KeySet:
        with open(keyset_file, "r") as f:
            return jwk.KeySet.import_key_set(json.load(f))

    def run_generate(args):
        extra_params = {"alg": "dir", "jrfc_created_at": int(time.time())}
        keyset = jwk.KeySet.generate_key_set("oct", 256, extra_params)
        write_keyset(keyset, args.keyset_file)

    def run_add(args):
        extra_params = {"alg": "dir", "jrfc_created_at": int(time.time())}
        if args.kid:
            extra_params["kid"] = args.kid

        keyset = read_keyset(args.keyset_file)
        keyset.generate_new_key("oct", 256, extra_params)
        write_keyset(keyset, args.keyset_file)

    def run_remove(args):
        if bool(args.kid) == bool(args.remove_oldest):
            print("Error: must provide exactly one of `--kid <id>` and `--remove-oldest`")
            args._print_help()
            sys.exit(1)

        keyset = read_keyset(args.keyset_file)

        if args.kid:
            keys_to_remove = [k for k in keyset if k.kid == args.kid]
        elif args.remove_oldest:
            keys_to_remove = sorted(keyset, key=lambda k: k.get("jrfc_created_at"))[:1]

        if args.disable:
            for k in keys_to_remove:
                k.jrfc_disabled = True
        else:
            keyset.remove_keys(keys_to_remove)

        write_keyset(keyset, args.keyset_file)

    match args.command:
        case Command.GENERATE:
            run_generate(args)
        case Command.ADD:
            run_add(args)
        case Command.REMOVE:
            run_remove(args)

Usage would look something like this:

.. code-block:: bash

    # Generate the keyset
    $ python manage-keyset.py generate keyset.json

    # Add a key to the keyset
    $ python manage-keyset.py add keyset.json

    # Disable the oldest key in the keyset
    $ python manage-keyset.py remove keyset.json --remove-oldest --disable

    # Remove the oldest key in the keyset
    $ python manage-keyset.py remove keyset.json --remove-oldest
