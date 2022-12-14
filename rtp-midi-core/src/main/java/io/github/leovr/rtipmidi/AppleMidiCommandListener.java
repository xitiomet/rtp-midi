package io.github.leovr.rtipmidi;

import io.github.leovr.rtipmidi.messages.AppleMidiClockSynchronization;
import io.github.leovr.rtipmidi.messages.AppleMidiInvitationAccepted;
import io.github.leovr.rtipmidi.messages.AppleMidiInvitationDeclined;
import io.github.leovr.rtipmidi.messages.AppleMidiInvitationRequest;
import io.github.leovr.rtipmidi.model.AppleMidiServerAddress;

import javax.annotation.Nonnull;

public interface AppleMidiCommandListener extends EndSessionListener {

    /**
     * This method is called for every invitation request.
     *
     * @param acceptance      The invitation request
     * @param appleMidiServer The origin server of this message
     */
    void onMidiInvitationAccepted(@Nonnull final AppleMidiInvitationAccepted acceptance,
                          @Nonnull final AppleMidiServerAddress appleMidiServer);

    /**
     * This method is called for every invitation request.
     *
     * @param acceptance      The invitation request
     * @param appleMidiServer The origin server of this message
     */
    void onMidiInvitationDeclined(@Nonnull final AppleMidiInvitationDeclined decline,
    @Nonnull final AppleMidiServerAddress appleMidiServer);
    /**
     * This method is called for every invitation request.
     *
     * @param invitation      The invitation request
     * @param appleMidiServer The origin server of this message
     */
    void onMidiInvitation(@Nonnull final AppleMidiInvitationRequest invitation,
                          @Nonnull final AppleMidiServerAddress appleMidiServer);

    /**
     * This method is called for every clock synchronization request.
     *
     * @param clockSynchronization The clock synchronization request
     * @param appleMidiServer      The origin server of this message
     */
    void onClockSynchronization(@Nonnull final AppleMidiClockSynchronization clockSynchronization,
                                @Nonnull final AppleMidiServerAddress appleMidiServer);

}
