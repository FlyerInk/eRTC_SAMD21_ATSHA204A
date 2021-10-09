from cryptoauthlib import *
from common import *
import time
import hashlib

# Safe input if using python 2
try: input = raw_input
except NameError: pass

# Example rootKey, store in Slot0
rootkey = bytearray.fromhex (
    '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
    '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

def test_mac(iface='hid', device='ecc', i2c_addr=None, keygen=True, **kwargs):
    ATCA_SUCCESS = 0x00

    # Loading cryptoauthlib(python specific)
    load_cryptoauthlib()

    # Get the target default config
    cfg = eval('cfg_at{}a_{}_default()'.format(atca_names_map.get(device), atca_names_map.get(iface)))

    # Set interface parameters
    if kwargs is not None:
        for k, v in kwargs.items():
            icfg = getattr(cfg.cfg, 'atca{}'.format(iface))
            setattr(icfg, k, int(v, 16))

    # Basic Raspberry Pi I2C check
    if 'i2c' == iface and check_if_rpi():
        cfg.cfg.atcai2c.bus = 1

    # Initialize the stack
    assert atcab_init(cfg) == ATCA_SUCCESS

    # Check device type
    info = bytearray(4)
    assert atcab_info(info) == ATCA_SUCCESS
    dev_name = get_device_name(info)
    dev_type = get_device_type_id(dev_name)

    # Reinitialize if the device type doesn't match the default
    if dev_type != cfg.devtype:
        cfg.dev_type = dev_type
        assert atcab_release() == ATCA_SUCCESS
        time.sleep(1)
        assert atcab_init(cfg) == ATCA_SUCCESS

    # Request the Serial Number
    serial_number = bytearray(9)
    assert atcab_read_serial_number(serial_number) == ATCA_SUCCESS
    print('Serial number: ')
    print(pretty_print_hex(serial_number, indent='    '))
    
    # Check the device locks
    print('Check Device Locks')
    is_locked = AtcaReference(False)
    assert atcab_is_locked(0, is_locked) == ATCA_SUCCESS
    config_zone_locked = bool(is_locked.value)
    print('    Config Zone is %s' % ('locked' if config_zone_locked else 'unlocked'))

    assert atcab_is_locked(1, is_locked) == ATCA_SUCCESS
    data_zone_locked = bool(is_locked.value)
    print('    Data Zone is %s' % ('locked' if data_zone_locked else 'unlocked'))

    # Run a nonce command to get a random data
    seed_in = bytearray.fromhex(
        '22 22 22 22 22 22 22 22 22 22  22 22 22 22 22 22 22 22 22 22')
    randout = bytearray(32)
    assert atcab_nonce_rand(seed_in, randout) == ATCA_SUCCESS
    print('Challenge: ')
    print(pretty_print_hex(randout, indent='    '))

    # Run a MAC command with Slot0, Slot0 have programmed with customers secure key
    digest = bytearray(32)
    assert atcab_mac(0x01, 0, 0, digest) == ATCA_SUCCESS
    print('MAC Digest: ')
    print(pretty_print_hex(digest, indent='    '))
    
    # Get Tempkey from randout
    hashBytes = bytearray.fromhex('16 00 00')
    inputdata = randout + seed_in + hashBytes
    sha256 = hashlib.sha256()
    sha256.update(inputdata)
    tempkey = sha256.digest()
    print('Tempkey: ')
    print(pretty_print_hex(tempkey, indent='    '))

    # Get Host MAC from RootKey + SN + SN Pad + ...
    macbytes = bytearray.fromhex(
        '08 01 00 00 00 00 00 00'
        '00 00 00 00 00 00 00 EE'
        '00 00 00 00 01 23 00 00')
    inputdata = rootkey + tempkey + macbytes
    sha256 = hashlib.sha256()
    sha256.update(inputdata)
    sw_digest = sha256.digest()
    print('SW Digest: ')
    print(pretty_print_hex(sw_digest, indent='    '))

    if sw_digest == digest:
        print('MAC Verify Success!\n')
    else:
        print('MAC Verify Fail!\n')

    atcab_release()

if __name__ == '__main__':
    parser = setup_example_runner(__file__)
    parser.add_argument('--i2c', help='I2C Address (in hex)')
    parser.add_argument('--gen', default=True, help='Generate new keys')
    args = parser.parse_args()

    if args.i2c is not None:
        args.i2c = int(args.i2c, 16)

    print('\nTest MAC Starting...\n')
    test_mac(args.iface, args.device, args.i2c, args.gen, **parse_interface_params(args.params))
