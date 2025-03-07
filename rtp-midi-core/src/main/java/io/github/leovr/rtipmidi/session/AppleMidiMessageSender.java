package io.github.leovr.rtipmidi.session;

import io.github.leovr.rtipmidi.messages.AppleMidiMessage;
import io.github.leovr.rtipmidi.model.AppleMidiServerAddress;

import javax.annotation.Nonnull;
import java.io.IOException;

/**
 * An implementation of this interface is responsible for sending {@link AppleMidiMessage}s to {@link
 * AppleMidiServerAddress}s.
 */
public interface AppleMidiMessageSender {

    /**
     * Sends the provided {@link AppleMidiMessage} to the corrresponding {@link AppleMidiServerAddress}
     *
     * @param appleMidiMessage The message to send
     * @param appleMidiServer  The target server
     * @throws IOException When a communication failure happens
     */
    void send(@Nonnull final AppleMidiMessage appleMidiMessage, @Nonnull final AppleMidiServerAddress appleMidiServer) throws
            IOException;
}
