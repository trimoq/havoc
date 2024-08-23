package dev.amann.msync_test;

import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.util.concurrent.TimeUnit;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws Exception {
        RandomAccessFile file = new RandomAccessFile("file.bin", "rw");
        MappedByteBuffer channel = file.getChannel().map(FileChannel.MapMode.READ_WRITE, 0, 512);
        while(true) {
            channel.put(0, (byte) 42);
            channel.force();
            System.out.println("Synced buffer");
            TimeUnit.MILLISECONDS.sleep(500);
        }
    }
}
