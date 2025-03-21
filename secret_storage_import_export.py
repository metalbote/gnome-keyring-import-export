#!/usr/bin/env python3

# Simple script for exporting gnome2 (seahorse) keyrings,
# using the SecretService API.

# Requirements:
#
# Python 3.5+
#
# secretstorage module. You can install this with:
#
#  pip install secretstorage

# Usage:
#
# 1) Export:
#
#   python secret_service_export.py export somefile.json
#
# Please note - this dumps all your passwords *unencrypted*
# into somefile.json
#
# 2) Import:
#
#    python secret_service_export.py import <input_file.json>

import json
import sys
import urllib
import base64
import secretstorage
import lxml.etree
from lxml.etree import Element


def mk_copy(item):
    """
    Makes a copy of the provided item and its attributes.

    A deep copy of the provided dictionary item is created by copying the
    dictionary itself and ensuring its 'attributes' field, if present, is also
    individually copied.

    Args:
        item (dict): The dictionary object to be copied.

    Returns:
        dict: A deep copy of the provided dictionary with its 'attributes' field
        also copied.
    """
    c = item.copy()
    c['attributes'] = c['attributes'].copy()
    return c


def remove_insignificant_data(item, ignore_secret=False):
    """
    Removes insignificant or sensitive data from a given item. This function modifies
    the provided item dictionary by removing specific keys and nested dictionary keys
    intended to hide or clean up data that is not essential for further processing.
    Optionally, sensitive data like 'secret' can be excluded based on the provided flag.

    Args:
        item (dict): The dictionary containing data that needs cleanup or sanitization
                     by removing specific keys or nested dictionary keys.
        ignore_secret (bool): A flag indicating whether the 'secret' key should also
                              be removed from the dictionary. Defaults to False.
    """
    item.pop('mtime', None)
    item.pop('ctime', None)
    item['attributes'].pop('date_created', None)
    if ignore_secret:
        item.pop('secret', None)


def items_roughly_equal(item1, item2, ignore_secret=False):
    """
    Determine if two items are approximately equal by modifying them to ignore
    insignificant differences.

    The function creates copies of the input items and removes insignificant
    data accordingly. This can optionally ignore secret-related differences
    between the items. Finally, it compares the modified copies to evaluate
    whether they are roughly equal.

    Parameters:
        item1: Any
            The first item to be compared.
        item2: Any
            The second item to be compared.
        ignore_secret: bool, optional
            Whether to ignore data related to secrets when making the comparison;
            defaults to False.

    Returns:
        bool
            True if the items are roughly equal after modification, otherwise False.
    """
    c1 = mk_copy(item1)
    c2 = mk_copy(item2)

    remove_insignificant_data(c1, ignore_secret=ignore_secret)
    remove_insignificant_data(c2, ignore_secret=ignore_secret)

    return c1 == c2


def export_keyrings(to_file):
    """
    Exports GNOME keyrings to a specified file in JSON format.

    This function retrieves all GNOME keyrings using the get_gnome_keyrings
    function, serializes them to a JSON structure, and writes the resulting
    data into a specified file. If an error occurs during any step of this
    process, it will log the error message to the standard error stream.

    Args:
        to_file (str): Path to the file where exported keyrings will be
                       saved in JSON format.

    Raises:
        Exception: Generic exception raised when an error occurs during
                   the export process (e.g., file I/O or serialization).
    """
    try:
        keyrings = get_gnome_keyrings()
        with open(to_file, "w") as f:
            f.write(json.dumps(keyrings, indent=2))
        print(f"Exported keyrings to {to_file}")
    except Exception as e:
        sys.stderr.write(f"Error exporting keyrings: {e}\n")


def import_keyrings(from_file):
    """
        Imports keyrings and associated items from a JSON file into the default secret storage
        collection. This method reads a JSON file containing keyring data, processes each item,
        and creates entries in the default secret storage if they do not already exist.

        Parameters:
            from_file: str
                Path to the JSON file containing keyrings and their associated items.

        Raises:
            Exception
                If there is an error while reading the file, processing the keyrings, or
                interacting with the secret storage backend.
    """
    try:
        with open(from_file, "r") as f:
            keyrings = json.load(f)

        connection = secretstorage.dbus_init()

        # Use 'default' alias if other aliases are not supported
        default_collection = None
        try:
            default_collection = secretstorage.get_default_collection(connection)
        except secretstorage.exceptions.SecretStorageException as e:
            sys.stderr.write(f"Error getting default collection: {e}\n")
            return

        for keyring_name, keyring_items in keyrings.items():
            print(f"Importing for keyring: {keyring_name}")
            for item_data in keyring_items:
                try:
                    # Check if item already exists
                    existing_items = list(default_collection.search_items(item_data['attributes']))
                    if existing_items and items_roughly_equal(
                            get_item_info(existing_items[0]), item_data, ignore_secret=True
                    ):
                        sys.stderr.write(f"Skipping existing entry: {item_data['display_name']}\n")
                        continue

                    # Create new item if it doesn't exist
                    secret = item_data['secret']
                    if not isinstance(secret, bytes):
                        # If secret value is base64 encoded, decode it
                        try:
                            secret = base64.b64decode(secret)
                        except Exception:
                            pass  # If decoding fails, keep value as string

                    default_collection.create_item(
                        label=item_data.get('display_name', 'Unnamed Item'),
                        attributes=item_data.get('attributes', {}),
                        secret=secret,
                    )

                    print(f"Imported: {item_data['display_name']}")
                except Exception as e:
                    sys.stderr.write(f"Error importing {item_data.get('display_name', 'Unknown')}: {e}\n")
    except Exception as e:
        sys.stderr.write(f"Error reading file {from_file}: {e}\n")


def get_gnome_keyrings():
    """
    Retrieve all GNOME keyrings and their respective items.

    This function connects to the Secret Service using the
    `secretstorage` library, fetches all available keyring collections,
    and retrieves information for all items within each keyring. The
    information about the keyrings and items is then organized in a
    dictionary, where the key is the keyring name and the value is a list
    of item details for that keyring.

    Returns
    -------
    dict
        A dictionary where keys are the names of GNOME keyrings and values
        are lists of item details associated with each keyring.
    """
    connection = secretstorage.dbus_init()
    keyrings = {}
    for collection in secretstorage.get_all_collections(connection):
        keyring_name = collection.collection_path
        keyrings[keyring_name] = [get_item_info(i) for i in list(collection.get_all_items())]

    return keyrings


def export_chrome_to_firefox(to_file):
    """
        Exports saved Chrome passwords stored in GNOME keyrings to a file in a
        Firefox-compatible XML format.

        This function retrieves password items from GNOME keyrings, filters
        them for Chrome-related credentials, and writes them to a specified
        output file in a format that Firefox can import.

        Parameters
        ----------
        to_file : str
            The file path where the Firefox-compatible XML file will be saved.
    """
    try:
        keyrings = get_gnome_keyrings()
        items = []
        item_set = set()

        for keyring_name, keyring_items in keyrings.items():
            for item in keyring_items:
                attribs = item.get('attributes', {})
                if (not item['display_name'].startswith('http') and
                        not attribs.get('application', '').startswith('chrome')):
                    continue
                items.append(item)

                item_def = (
                    attribs.get('signon_realm', ''),
                    attribs.get('username_value', ''),
                    attribs.get('action_url', ''),
                    attribs.get('username_element', ''),
                    attribs.get('password_element', '')
                )
                if item_def in item_set:
                    sys.stderr.write("Warning: duplicate found for %r\n\n" % (item_def,))
                item_set.add(item_def)

        xml = items_to_firefox_xml(items)
        with open(to_file, "w") as f:
            f.write(xml.decode('utf-8'))
        print(f"Exported Chrome passwords as Firefox-compatible XML to {to_file}")
    except Exception as e:
        sys.stderr.write(f"Error exporting Chrome passwords: {e}\n")


def items_to_firefox_xml(items):
    """
    Converts a list of credential items into Firefox XML format.

    This function processes a list of credential dictionaries and generates
    a Firefox-compatible XML file containing saved password information.
    The resulting XML can be used to import credentials into Firefox using
    the "Password Exporter" extension.

    Args:
        items (list[dict]): A list of dictionaries, where each dictionary
        represents credential information. Each dictionary must contain
        an `attributes` key with subkeys such as 'signon_realm', 'username_value',
        or other related metadata.

    Returns:
        bytes: A byte-string representing the generated XML document in
        Firefox-compatible format. The XML contains entries with hostnames,
        usernames, passwords, and additional credential metadata.

    Raises:
        KeyError: Raised if any required keys are missing in the provided input
        dictionaries.
    """
    doc = Element('xml')
    entries = Element('entries',
                      dict(ext="Password Exporter", extxmlversion="1.1", type="saved", encrypt="false"))
    doc.append(entries)
    for item in items:
        attribs = item['attributes']
        url = urllib.parse.urlparse(attribs.get('signon_realm', ''))
        if not url.scheme or not url.netloc:
            continue
        entries.append(Element('entry',
                               dict(host=url.scheme + "://" + url.netloc,
                                    user=attribs.get('username_value', ''),
                                    password=item.get('secret', ''),
                                    formSubmitURL=attribs.get('action_url', ''),
                                    httpRealm=url.path.lstrip('/'),
                                    userFieldName=attribs.get('username_element', ''),
                                    passFieldName=attribs.get('password_element', ''),
                                    )))
    return lxml.etree.tostring(doc, pretty_print=True)


def get_item_info(item):
    """
    Fetches information about a given item, including its display name, secret, timestamps,
    and attributes, while handling decoding and potential errors gracefully.

    Parameters:
        item: The item object from which to retrieve information.

    Returns:
        dict: A dictionary containing the keys:
            - 'display_name' (str): The label or display name of the item.
            - 'secret' (str): The decoded or base64-encoded secret associated with the item.
            - 'mtime' (float): The last modified time of the item.
            - 'ctime' (float): The creation time of the item.
            - 'attributes' (dict): A dictionary of attributes related to the item.
    """
    try:
        item.unlock()
        secret = item.get_secret()
        try:
            secret = secret.decode('utf-8')  # Try decoding the secret as UTF-8
        except UnicodeDecodeError:
            # If decoding fails, base64 encode the binary secret
            import base64
            secret = base64.b64encode(secret).decode('utf-8')  # Encode binary data to base64

        return {
            'display_name': item.get_label(),
            'secret': secret,
            'mtime': item.get_modified(),
            'ctime': item.get_created(),
            'attributes': item.get_attributes(),
        }
    except Exception as e:
        sys.stderr.write(f"Error accessing item {item.get_label()}: {e}\n")
        return {}


if __name__ == '__main__':
    if len(sys.argv) == 3:
        command, file_name = sys.argv[1], sys.argv[2]

        if command == "export":
            export_keyrings(file_name)
        elif command == "export_chrome_to_firefox":
            export_chrome_to_firefox(file_name)
        elif command == "import":
            import_keyrings(file_name)
        else:
            print("Error: Unsupported command. Use 'export', 'export_chrome_to_firefox', or 'import'.")
            sys.exit(1)
    else:
        print("""
Usage:
  python secret_service_export.py export <output_file.json>
  python secret_service_export.py export_chrome_to_firefox <output_file.xml>
  python secret_service_export.py import <input_file.json>
  
  See source code for more info
""")
        sys.exit(1)
