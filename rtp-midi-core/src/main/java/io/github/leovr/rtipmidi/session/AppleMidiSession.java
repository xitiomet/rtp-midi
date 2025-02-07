package io.github.leovr.rtipmidi.session;

import io.github.leovr.rtipmidi.AppleMidiCommandListener;
import io.github.leovr.rtipmidi.AppleMidiMessageListener;
import io.github.leovr.rtipmidi.messages.AppleMidiClockSynchronization;
import io.github.leovr.rtipmidi.messages.AppleMidiEndSession;
import io.github.leovr.rtipmidi.messages.AppleMidiInvitationRequest;
import io.github.leovr.rtipmidi.messages.MidiCommandHeader;
import io.github.leovr.rtipmidi.model.AppleMidiServerAddress;
import io.github.leovr.rtipmidi.model.MidiMessage;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import javax.annotation.Nonnull;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.Random;

/**
 * This class represents a single MIDI session with a remote server. It simplifies the methods of {@link
 * AppleMidiMessageListener} and {@link AppleMidiCommandListener} for the subclasses.
 */
@Slf4j
@Getter
@Setter
public abstract class AppleMidiSession implements AppleMidiMessageListener, AppleMidiCommandListener {

    private long offsetEstimate;
    private ArrayList<AppleMidiSessionSender> senders = new ArrayList<AppleMidiSessionSender>();
    @Setter
    protected int timestampOffset = new Random().nextInt();

    /**
     * Returns the current timestamp in 100 microseconds. The default implementation uses the JVM startup time as
     * reference.
     *
     * @return The timestamp in 100 microseconds or -1 if the session does not care about the timestamp
     */
    public long getCurrentTimestamp() {
        return timestampOffset + ManagementFactory.getRuntimeMXBean().getUptime() * 10;
    }

    @Override
    public final void onMidiMessage(final MidiCommandHeader midiCommandHeader, final MidiMessage message,
                                    final int timestamp) {
        onMidiMessage(message, timestamp + offsetEstimate);
    }

    /**
     * Called for every received MIDI messages
     *
     * @param message   The MIDI message
     * @param timestamp The timestamp of the message
     */
    protected abstract void onMidiMessage(final MidiMessage message, final long timestamp);

    /**
     * Sends the provided MIDI-message via {@link AppleMidiSessionSender}
     *
     * @param message   The {@link MidiMessage} to deliver
     * @param timestamp The timestamp of the message
     */
    public void sendMidiMessage(final MidiMessage message, final long timestamp) {
        senders.forEach((sender) -> {
            sender.sendMidiMessage(message, timestamp);
        });
    }

    public void addSender(AppleMidiSessionSender sender)
    {
        if (!senders.contains(sender))
            senders.add(sender);
    }

    public void removeSender(AppleMidiSessionSender sender)
    {
        if (senders.contains(sender))
            senders.remove(sender);
    }

    @Override
    public final void onMidiInvitation(@Nonnull final AppleMidiInvitationRequest invitation,
                                       @Nonnull final AppleMidiServerAddress appleMidiServer) {
    }

    @Override
    public final void onClockSynchronization(@Nonnull final AppleMidiClockSynchronization clockSynchronization,
                                             @Nonnull final AppleMidiServerAddress appleMidiServer) {
    }

    @Override
    public final void onEndSession(@Nonnull final AppleMidiEndSession appleMidiEndSession,
                                   @Nonnull final AppleMidiServerAddress appleMidiServer) {
        onEndSession();
    }

    /**
     * Called on end session. Any clean-up can happen here.
     */
    protected void onEndSession() {
    }
}
