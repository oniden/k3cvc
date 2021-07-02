package in.k3c.violcipher;

import java.io.IOException;
import java.io.InputStream;
import java.util.Random;
import java.util.stream.IntStream;

public class K3CVCDecrypt extends InputStream {
    private byte[] buffer;
    Random         prng;
    InputStream    in;
    int            maxRounds;
    
    K3CVCDecrypt(InputStream in, long key, int maxRounds) {
	this.in = in;
	this.maxRounds = maxRounds+1;
	this.prng = new Random(key);
	this.buffer = new byte[IntStream.range(0, this.maxRounds+1)
      					.map(n -> (int)Math.pow(8, n))
      					.sum()];
    }
    
    @Override
    public int read() throws IOException {
	int rounds = prng.nextInt(maxRounds)+1;
	int inoff = 0;
	int inlen = (int)Math.pow(8, rounds);
	int outlen = inlen / 8;
	
	// if cannot read to the size of the encoded part
	// its a failure already!
	in.readNBytes(buffer, 0, inlen);
	
	for(int n = 0; n < rounds; ++n) {
	    int outoff = inoff + inlen;
	    
	    for(int i = 0; i < outlen; ++i) {
		// zero it, as leftovers from previous OP could be there.
		buffer[i + outoff] = 0;
		
		for(int j = 0; j < 8; ++j) {
		    byte d = buffer[i*8 + (7-j) + inoff];
		    
		    if(d != '-' && d != '\'')
			throw new IOException("Data is violed '-'");
		    
		    buffer[i + outoff] |= (byte)((d == '\'' ? 1 : 0) << j);
		}
	    }
	    
	    inoff += inlen;      // slide to its  decoded part.
	    inlen  = outlen;     // decoded parts length is made its length.
	    outlen = outlen / 8; // next output's length is (1/8)x the decoded.
	}
	
	// it will always produce a single char at end very end.
	return buffer[inoff];
    }
}
