#/bin/sh

# Need to run this as superuser

function gadget_prepare {
    cd /sys/kernel/config/usb_gadget
    mkdir -p g1/strings/0x409
    cd g1
    echo 0x18d1 > idVendor  # Google
    echo 0x0104 > idProduct # Multifunction Composite USB Gadget
    echo 0x0100 > bcdDevice # v1.0.0
    echo 0x0300 > bcdUSB # Superspeed
    echo "0123456789abcdef" > strings/0x409/serialnumber
    echo "Google Inc." > strings/0x409/manufacturer
    echo "VSoC USB Test Device" > strings/0x409/product
    mkdir -p configs/c.1/strings/0x409/
    echo "Config: Test Configuration" > configs/c.1/strings/0x409/configuration
    mkdir -p functions/mass_storage.usb0
    ln -s functions/mass_storage.usb0 configs/c.1
    echo "vsoc_usb_udc.0" > UDC
    #echo "dummy_hcd.0" > UDC
    cd $HOME
}

while getopts p: opt "$@"
do
    case "${opt}"
    in
    p) modfullpath=${OPTARG}
       modprobe libcomposite
       insmod "${modfullpath}"
#       modprobe dummy_hcd
       gadget_prepare
        ;;
    esac
done
