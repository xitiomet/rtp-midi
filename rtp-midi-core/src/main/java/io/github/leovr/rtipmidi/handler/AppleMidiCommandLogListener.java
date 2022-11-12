package io.github.leovr.rtipmidi.handler;

import io.github.leovr.rtipmidi.AppleMidiCommandListener;
import io.github.leovr.rtipmidi.messages.AppleMidiEndSession;
import io.github.leovr.rtipmidi.messages.AppleMidiInvitationAccepted;
import io.github.leovr.rtipmidi.messages.AppleMidiInvitationDeclined;
import io.github.leovr.rtipmidi.model.AppleMidiServer;
import io.github.leovr.rtipmidi.messages.AppleMidiClockSynchronization;
import io.github.leovr.rtipmidi.messages.AppleMidiInvitationRequest;
import lombok.extern.slf4j.Slf4j;

import javax.annotation.Nonnull;

@Slf4j
class AppleMidiCommandLogListener implements AppleMidiCommandListener {

    @Override
    public void onMidiInvitation(@Nonnull final AppleMidiInvitationRequest invitation, @Nonnull final AppleMidiServer appleMidiServer) {
        log.trace("MIDI invitation: invitation: {}, appleMidiServer: {}", invitation, appleMidiServer);
    }

    @Override
    public void onClockSynchronization(@Nonnull final AppleMidiClockSynchronization clockSynchronization,
                                       @Nonnull final AppleMidiServer appleMidiServer) {
        log.trace("MIDI clock synchronization: clockSynchronization: {}, appleMidiServer: {}", clockSynchronization,
                appleMidiServer);
    }

    @Override
    public void onEndSession(@Nonnull final AppleMidiEndSession appleMidiEndSession, @Nonnull final AppleMidiServer appleMidiServer) {
        log.trace("MIDI end session: appleMidiEndSession: {}, appleMidiServer: {}", appleMidiEndSession,
                appleMidiServer);
    }

    @Override
    public void onMidiInvitationAccepted(@Nonnull AppleMidiInvitationAccepted acceptance,
            @Nonnull AppleMidiServer appleMidiServer) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void onMidiInvitationDeclined(@Nonnull AppleMidiInvitationDeclined decline,
            @Nonnull AppleMidiServer appleMidiServer) {
        // TODO Auto-generated method stub
        
    }
}
