package io.github.leovr.rtipmidi.model;

import lombok.Value;

import javax.annotation.Nonnull;
import java.net.InetAddress;

/**
 * A remote server representation consisting of port and {@link InetAddress}
 */
@Value
public class AppleMidiServerAddress {

    @Nonnull
    private InetAddress inetAddress;
    private int port;
}
