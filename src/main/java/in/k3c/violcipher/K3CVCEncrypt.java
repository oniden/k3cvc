package in.k3c.violcipher;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;
import java.util.stream.IntStream;

public class K3CVCEncrypt extends OutputStream {
    private byte[] buffer;
    Random         prng;
    OutputStream   out;
    int            maxRounds;
    
    K3CVCEncrypt(OutputStream out, long key, int maxRounds) {
	this.out = out;
	this.maxRounds = maxRounds+1;
	this.prng = new Random(key);
	this.buffer = new byte[IntStream.range(0, this.maxRounds+1)
	       				.map(n -> (int)Math.pow(8, n))
	       				.sum()];
    }
    
    @Override
    public void write(int b) throws IOException {
	// The idea is that, instead of multiple allocations we use a single buffer
	// that stores layered data 
	
	int inoff  = 0;
	int inlen  = 1;  // length of the input
	int outlen = 8;  // because the full buffer may be unused.
	int rounds = prng.nextInt(maxRounds)+1; // shouldn't be zero.
	
	buffer[0] = (byte)b;
	
	for(int n = 0; n < rounds; ++n) {
	    // output is stored as adjacent to input.
	    int outoff = inoff + inlen;
	    
	    for(int i = 0; i < inlen; ++i)
		for(int j = 0; j < 8; ++j)
		    buffer[i*8 + (7-j) + outoff] = (byte)((buffer[i + inoff] >> j & 1) == 1 ? '\'' : '-');
	    
	    inoff  = outoff;     // slide to its encoded part.
	    inlen  = outlen;     // encoded parts length is made its length.
	    outlen = outlen * 8; // next output's length is 8x the encoded.
	}
	
	// because the last output becomes the input in processing the next one
	// for the final one, there's no processing required for the last one
	// so we write the current input (aka. the final output).
	out.write(buffer, inoff, inlen);
    }
}
