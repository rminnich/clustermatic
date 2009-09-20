# bootconfig
#
# $Id: config.boot,v 1.2 2004/04/19 17:07:31 mkdist Exp $

# PCI Configuration list:
#
# This file should only contain ID's for PCI devices which are to be
# used boot time.  Every module referenced here will be included in
# the phase 2 boot image.
#
# This syntax might change to allow module parameters instead.

# These are the modules to include in the phase 1 and 2 boot images.
# This should generally include network drivers only.  If your image
# becomes too large to fit on your boot media (e.g. a floppy), try
# including only the drivers you need.

# Beoboot will now automatically gather all the network drivers it can
# find.  Use --noautomod to prevent this behavior.

# To force inclusion of other modules do something like:
# bootmodule pcnet32


# PPC: These don't appear on the PCI bus so we have to force them in
# like this on PPC systms:
# Macs should uncomment these...
#bootmodule gmac bmac
#modprobe gmac
#modprobe bmac
