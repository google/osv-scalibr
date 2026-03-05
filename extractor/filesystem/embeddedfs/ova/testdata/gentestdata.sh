#!/usr/bin/env bash

# Create placeholder OVF XML file
cat > valid.ovf <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://schemas.dmtf.org/ovf/envelope/1 ovf.xsd">
  <References/>
  <DiskSection>
    <Info>Virtual disk information</Info>
  </DiskSection>
  <VirtualSystem ovf:id="example-vm">
    <Info>Example placeholder virtual machine</Info>
    <Name>ExampleVM</Name>
  </VirtualSystem>
</Envelope>
EOF

# Create the OVA (which is just a tar archive of OVF and any disks)
tar -cvf valid.ova valid.ovf > /dev/null
rm valid.ovf

echo "Yuvraj Saxena <ysaxenax@gmail.com>" > invalid.ova
