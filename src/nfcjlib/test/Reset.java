/* ****************************************
 * Copyright (c) 2013, Daniel Andrade
 * All rights reserved.
 * 
 * (1) Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. (2) Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution. (3) The name of the author may not be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * Modified BSD License (3-clause BSD)
 */
package nfcjlib.test;

import nfcjlib.core.DESFireEV1;
import nfcjlib.core.DESFireEV1.KeyType;
import nfcjlib.core.DESFireEV2;
import nfcjlib.core.util.DesfireDiversification;
import nfcjlib.core.util.DesfireUtils;

class Reset {

	static byte[] damAuthKey = DesfireUtils.hexStringToByteArray("F03C21DF275F23ED2FB0F420B2E15AB9");
	static byte[] damMacKey = DesfireUtils.hexStringToByteArray("41F23FB097ADDABE1195C0E096204A2F");
	static byte[] damEncKey = DesfireUtils.hexStringToByteArray("A580B1A4D014DB32219F756F3A2B3471");

	public static void main(String[] args) throws Exception {
		DESFireEV2 desfire = new DESFireEV2();
		desfire.connect();

		desfire.selectApplication(new byte[] {0x00, 0x00, 0x00});
		desfire.authenticate(new byte[16], (byte) 0x00, KeyType.AES);

		desfire.formatPICC();

		desfire.resetDamKeys(damAuthKey, damMacKey, damEncKey);

		desfire.disconnect();
	}

}