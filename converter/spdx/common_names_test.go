// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spdx_test

import (
	"testing"

	"github.com/google/osv-scalibr/converter/spdx"
)

func TestCommonLicenseNames(t *testing.T) {
	tests := []struct{ commonName, shortIdentifier string }{
		{"0bsd", "0BSD"},
		{"ASWFDA1", "ASWF-Digital-Assets-1.0"},
		{"AdobeDP", ""},
		{"AdobeD-PostScript", "Adobe-Display-PostScript"},
		{"ARTISTIC1.0-PERL", "Artistic-1.0-Perl"},
		{"ARTISTIC1.0P", "Artistic-1.0-Perl"},
		{"ARTISTIC1.0PERL", "Artistic-1.0-Perl"},
		{"Artistic1P", "Artistic-1.0-Perl"},
		{"Artistic1Perl", "Artistic-1.0-Perl"},
		{"BSDSC", "BSD-Source-Code"},
		{"BSDS-beginning-file", "BSD-Source-beginning-file"},
		{"CC0-1", "CC0-1.0"},
		{"CC0-1.0", "CC0-1.0"},
		{"CC01", "CC0-1.0"},
		{"CC01.0", "CC0-1.0"},
		{"CC-BY3", "CC-BY-3.0"},
		{"CC-BY3.0", "CC-BY-3.0"},
		{"CCBY3", "CC-BY-3.0"},
		{"CCBY3.0", "CC-BY-3.0"},
		{"CECILLB", "CECILL-B"},
		{"CECILLC", "CECILL-C"},
		{"CERNOHL1.1", "CERN-OHL-1.1"},
		{"CMU", ""},
		{"CMUM", "CMU-Mach"},
		{"CMUMach", "CMU-Mach"},
		{"CNRIJ", "CNRI-Jython"},
		{"CNRIP", "CNRI-Python"},
		{"cornelll-jpeg", "Cornell-Lossless-JPEG"},
		{"DocBookS", "DocBook-Schema"},
		{"FSFAPnowarrantydisclaimer", "FSFAP-no-warranty-disclaimer"},
		{"FSFAPnwd", ""},
		{"GPL2-with-GCC-exception", "GPL-2.0-with-GCC-exception"},
		{"GPL2.0-with-GCC-exception", "GPL-2.0-with-GCC-exception"},
		{"GPL2with-GCC-exception", "GPL-2.0-with-GCC-exception"},
		{"GPL2.0with-GCC-exception", "GPL-2.0-with-GCC-exception"},
		{"GPL2withGCCexception", "GPL-2.0-with-GCC-exception"},
		{"GPL2.0withGCCexception", "GPL-2.0-with-GCC-exception"},
		{"GPL2withGCCexception", "GPL-2.0-with-GCC-exception"},
		{"GPL2.0withGCCexception", "GPL-2.0-with-GCC-exception"},
		{"GraphicsG", "Graphics-Gems"},
		{"HPNDFL", "HPND-Fenneberg-Livingston"},
		{"IECcc-Eula", "IEC-Code-Components-EULA"},
		{"LGPL2", "LGPL-2.0-only"},
		{"LGPL2+", "LGPL-2.0-or-later"},
		{"MartinB", "Martin-Birgmeier"},
		{"MSPL", "MS-PL"},
		{"MSRL", "MS-RL"},
		{"MIT0", "MIT-0"},
		{"MITCMU", "MIT-CMU"},
		{"PHP3", "PHP-3.0"},
		{"PolyForm-Noncommercial1", "PolyForm-Noncommercial-1.0.0"},
		{"PolyForm-Noncommercial1.0", "PolyForm-Noncommercial-1.0.0"},
		{"PolyForm-Noncommercial1.0.0", "PolyForm-Noncommercial-1.0.0"},
		{"PolyFormN1", "PolyForm-Noncommercial-1.0.0"},
		{"PolyFormN1.0", "PolyForm-Noncommercial-1.0.0"},
		{"PolyFormN1.0.0", "PolyForm-Noncommercial-1.0.0"},
		{"PolyForm-Small-Business1", "PolyForm-Small-Business-1.0.0"},
		{"PolyForm-Small-Business1.0", "PolyForm-Small-Business-1.0.0"},
		{"PolyForm-Small-Business1.0.0", "PolyForm-Small-Business-1.0.0"},
		{"PolyFormSB1", "PolyForm-Small-Business-1.0.0"},
		{"PolyFormSB1.0", "PolyForm-Small-Business-1.0.0"},
		{"PolyFormSB1.0.0", "PolyForm-Small-Business-1.0.0"},
		{"QPL1.0I2004", ""},
		{"QPL1I2004", ""},
		{"QPL1.0INRIA2004", "QPL-1.0-INRIA-2004"},
		{"QPL1INRIA2004", "QPL-1.0-INRIA-2004"},
		{"RHeCos1", ""},
		{"RHeCos1.1", "RHeCos-1.1"},
		{"RHeCos11", ""},
	}

	for _, tc := range tests {
		t.Run(tc.commonName, func(t *testing.T) {
			got, ok := spdx.ShortIdentifier(tc.commonName)
			if got == "" && ok {
				t.Fatalf("spdx.ShortIdentifier(%q) found empty short identifier (%q): got ok==%v, want ok==false", tc.commonName, got, ok)
			}
			if got != tc.shortIdentifier {
				t.Errorf("spdx.ShortIdentifier(%q) got %q, want %q", tc.commonName, got, tc.shortIdentifier)
			}
		})
	}
}
