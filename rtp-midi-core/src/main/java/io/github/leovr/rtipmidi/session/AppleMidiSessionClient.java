package io.github.leovr.rtipmidi.session;

import io.github.leovr.rtipmidi.AppleMidiCommandListener;
import io.github.leovr.rtipmidi.AppleMidiMessageListener;
import io.github.leovr.rtipmidi.error.AppleMidiSessionServerRuntimeException;
import io.github.leovr.rtipmidi.handler.AppleMidiCommandHandler;
import io.github.leovr.rtipmidi.handler.AppleMidiMessageHandler;
import io.github.leovr.rtipmidi.messages.AppleMidiClockSynchronization;
import io.github.leovr.rtipmidi.messages.AppleMidiCommand;
import io.github.leovr.rtipmidi.messages.AppleMidiEndSession;
import io.github.leovr.rtipmidi.messages.AppleMidiInvitation;
import io.github.leovr.rtipmidi.messages.AppleMidiInvitationAccepted;
import io.github.leovr.rtipmidi.messages.AppleMidiInvitationDeclined;
import io.github.leovr.rtipmidi.messages.AppleMidiInvitationRequest;
import io.github.leovr.rtipmidi.messages.AppleMidiMessage;
import io.github.leovr.rtipmidi.messages.MidiCommandHeader;
import io.github.leovr.rtipmidi.messages.MidiTimestampPair;
import io.github.leovr.rtipmidi.messages.RtpHeader;
import io.github.leovr.rtipmidi.model.AppleMidiServerAddress;
import io.github.leovr.rtipmidi.model.MidiMessage;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;

import javax.annotation.Nonnull;
import javax.xml.crypto.Data;
import java.nio.ByteBuffer;
import java.nio.file.Paths;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The session server handles MIDI invitation, clock synchronin requests, as well as the MIDI messages. In order to
 * handle MIDI messages a {@link AppleMidiSession} has to be added via {@link #addAppleMidiSession(AppleMidiSession)}.
 * Otherwise all invitation requests are rejected. The session server must be run on a port which is {@code control port
 * + 1}
 */
@Slf4j
public class AppleMidiSessionClient implements AppleMidiCommandListener, AppleMidiMessageListener,
        AppleMidiMessageSender, AppleMidiSessionSender {

    private static final int SOCKET_TIMEOUT = 1000;
    private static final int RECEIVE_BUFFER_LENGTH = 1024;

    private ExecutorService executorService;
    private final int ssrc;
    private int remoteSsrc;
    private int initiatorToken;
    private final String localName;
    private final String remoteName;
    private final InetAddress inetAddress;
    private final int port;
    private final AppleMidiCommandHandler midiCommandHandler = new AppleMidiCommandHandler();
    private final AppleMidiMessageHandler midiMessageHandler = new AppleMidiMessageHandler();
    private boolean running = false;
    private DatagramSocket controlSocket;
    private DatagramSocket sessionSocket;
    private AppleMidiSession session;

    private final List<SessionChangeListener> sessionChangeListeners = new ArrayList<>();
    private Thread controlThread;
    private Thread sessionThread;
    private long lastClockSyncAt;
    private short sequenceNumber = (short) new Random().nextInt(Short.MAX_VALUE + 1);


    /**
     * @param name The name under which the other peers should see this server
     * @param port The session server port which must be {@code control port + 1}
     */
    public AppleMidiSessionClient(@Nonnull final String remoteName, final InetAddress inetAddress, final int port, @Nonnull final String localName) {
        this.port = port;
        this.remoteName = remoteName;
        this.localName = localName;
        this.ssrc = createSsrc(this.localName);
        this.inetAddress = inetAddress;
        midiCommandHandler.registerListener(this);
        midiMessageHandler.registerListener(this);
    }

    private int createSsrc(final String hostName) {
        try {
            final MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(String.valueOf(new Date().getTime()).getBytes());
            md.update(String.valueOf(System.identityHashCode(this)).getBytes());
            md.update(Paths.get("").toAbsolutePath().normalize().toString().getBytes());
            md.update(hostName.getBytes());
            final byte[] md5 = md.digest();
            int ssrc = 0;
            final ByteBuffer byteBuffer = ByteBuffer.wrap(md5);
            for (int i = 0; i < 3; i++) {
                ssrc ^= byteBuffer.getInt();
            }
            return ssrc;
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not get MD5 algorithm", e);
        }
    }

    public synchronized void start() 
    {
        this.running = true;
        this.lastClockSyncAt = 0;
        this.executorService = Executors.newCachedThreadPool();
        this.controlThread = new Thread(this.controlRunnable, this.remoteName + ".control");
        this.sessionThread = new Thread(this.sessionRunnable, this.remoteName + ".session");
        try {
            this.controlSocket = new DatagramSocket();
            this.controlSocket.setSoTimeout(SOCKET_TIMEOUT);
            this.controlSocket.connect(this.inetAddress, getControlPort());
            this.sessionSocket = new DatagramSocket();
            this.sessionSocket.setSoTimeout(SOCKET_TIMEOUT);
            this.sessionSocket.connect(this.inetAddress, getSessionPort());
        } catch (final SocketException e) {
            throw new AppleMidiSessionServerRuntimeException("DatagramSocket cannot be opened", e);
        }
        controlThread.start();
        sessionThread.start();
        log.debug("MIDI session client started");
        AppleMidiInvitationRequest invitation = new AppleMidiInvitationRequest(2, getNewInitiatorToken(), this.ssrc, this.localName);
        try
        {
            sendControl(invitation);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }

    public boolean isRunning()
    {
        return this.running;
    }

    public boolean isConnected()
    {
        if (this.sessionSocket != null && this.isRunning())
        {
            return this.sessionSocket.isConnected();
        }
        return false;
    }

    public boolean hasServerConnection(io.github.leovr.rtipmidi.AppleMidiServer server)
    {
        return server.hasConnection(this.remoteName, this.inetAddress, this.getSessionPort());
    }

    public String getRemoteName()
    {
        return this.remoteName;
    }

    public String getLocalName()
    {
        return this.localName;
    }

    public InetAddress getRemoteAddress()
    {
        return this.inetAddress;
    }

    public String getRemoteAddressString()
    {
        return this.getRemoteAddress().toString();
    }

    public int getControlPort()
    {
        return this.port;
    }

    public int getSessionPort()
    {
        return this.port + 1;
    }

    int getNewInitiatorToken() {
        return new Random().nextInt();
    }

    private Runnable controlRunnable = new Runnable()
    {
        @Override
        public void run() {
            while (running) {

                try {
                    final byte[] receiveDataControl = new byte[RECEIVE_BUFFER_LENGTH];
                    final DatagramPacket incomingPacketControl = new DatagramPacket(receiveDataControl, receiveDataControl.length);
                    controlSocket.receive(incomingPacketControl);
                    executorService.execute(new Runnable() {
                        @Override
                        public void run() {
                            if (receiveDataControl[0] == AppleMidiCommand.MIDI_COMMAND_HEADER1) {
                                //System.err.println("INCOMING CONTROL COMMAND PACKET");
                                midiCommandHandler.handle(receiveDataControl,
                                        new AppleMidiServerAddress(incomingPacketControl.getAddress(), incomingPacketControl.getPort()));
                            } else {
                                midiMessageHandler.handle(receiveDataControl,
                                        new AppleMidiServerAddress(incomingPacketControl.getAddress(), incomingPacketControl.getPort()));
                            }
                        }
                    });

                } catch (final SocketTimeoutException ignored) {
                } catch (final IOException e) {
                    log.error("IOException while receiving", e);
                } catch (final java.util.concurrent.RejectedExecutionException ree) {
                    
                }
                if ((System.currentTimeMillis() - AppleMidiSessionClient.this.lastClockSyncAt) > 10000 && AppleMidiSessionClient.this.lastClockSyncAt != 0 && running)
                {
                    try
                    {
                        sendClockSync();
                    } catch (Exception scsEx) {

                    }
                }
            }
            System.err.println("Closing Control socket");
            controlSocket.close();
            controlSocket = null;
        }
    };

    private Runnable sessionRunnable = new Runnable()
    {
        @Override
        public void run() {
            while (running) {
                try {
                    final byte[] receiveDataSession = new byte[RECEIVE_BUFFER_LENGTH];
                    final DatagramPacket incomingPacketSession = new DatagramPacket(receiveDataSession, receiveDataSession.length);
                    sessionSocket.receive(incomingPacketSession);
                    executorService.execute(new Runnable() {
                        @Override
                        public void run() {
                            if (receiveDataSession[0] == AppleMidiCommand.MIDI_COMMAND_HEADER1) {
                                //System.err.println("INCOMING SESSION COMMAND PACKET");
                                midiCommandHandler.handle(receiveDataSession,
                                        new AppleMidiServerAddress(incomingPacketSession.getAddress(), incomingPacketSession.getPort()));
                            } else {
                                midiMessageHandler.handle(receiveDataSession,
                                        new AppleMidiServerAddress(incomingPacketSession.getAddress(), incomingPacketSession.getPort()));
                            }
                        }
                    });
                } catch (final SocketTimeoutException ignored) {
                } catch (final IOException e) {
                    log.error("IOException while receiving", e);
                } catch (final java.util.concurrent.RejectedExecutionException ree) {

                }
            }
            System.err.println("Closing Session socket");
            sessionSocket.close();
            sessionSocket = null;
        }
    };

    public void invitePeerAgainViaSession(AppleMidiInvitationAccepted acceptance)
    {
        //System.err.println("Invite peer again");
        AppleMidiServerAddress outgoingServer = new AppleMidiServerAddress(this.inetAddress, getSessionPort());
        this.initiatorToken = acceptance.getInitiatorToken();
        AppleMidiInvitationRequest invitation = new AppleMidiInvitationRequest(2, this.initiatorToken, this.ssrc, this.localName);
        try
        {
            send(invitation, outgoingServer);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }

    /**
     * Shutds down all sockets and threads
     */
    public void stopClient()
    {
        try
        {
            AppleMidiEndSession goodbye = new AppleMidiEndSession(2, this.initiatorToken, this.ssrc);
            this.sendControl(goodbye);
        } catch (Exception e2) {
            e2.printStackTrace(System.err);
        }
        running = false;
        try
        {
            executorService.shutdown();
        } catch (Exception e) {}
        if (this.session != null)
            this.session.removeSender(this);
        log.debug("MIDI session server stopped");
    }

    private void sendControl(final AppleMidiCommand midiCommand) throws IOException {
        sendControl(midiCommand.toByteArray());
    }

    private void sendControl(final byte[] data) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("Sending data {} to server {}", Hex.encodeHexString(data));
        }
        //System.err.println("Sending Control Packet to " + this.inetAddress.toString() + ":" + String.valueOf(this.port));
        controlSocket.send(new DatagramPacket(data, data.length, this.inetAddress, this.getControlPort()));
    }

    public void sendControl(@Nonnull final AppleMidiMessage appleMidiMessage) throws IOException {
        sendControl(appleMidiMessage.toByteArray());
    }

    private void send(final AppleMidiCommand midiCommand, final AppleMidiServerAddress appleMidiServer) throws IOException {
        send(midiCommand.toByteArray(), appleMidiServer);
    }

    private void send(final byte[] data, final AppleMidiServerAddress appleMidiServer) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("Sending data {} to server {}", Hex.encodeHexString(data), appleMidiServer);
        }
        sessionSocket.send(new DatagramPacket(data, data.length, this.inetAddress, this.getSessionPort()));
    }

    @Override
    public void send(@Nonnull final AppleMidiMessage appleMidiMessage,
                     @Nonnull final AppleMidiServerAddress appleMidiServer) throws IOException {

        //System.err.println("SENDING SESSION MIDI DATAGRAM " + String.valueOf(appleMidiServer.getPort()));
        send(appleMidiMessage.toByteArray(), appleMidiServer);
    }

    @Override
    public void onMidiInvitation(@Nonnull final AppleMidiInvitationRequest invitation,
                                 @Nonnull final AppleMidiServerAddress appleMidiServer) {
        
    }

    @Override
    public void onMidiInvitationAccepted(@Nonnull AppleMidiInvitationAccepted acceptance,
            @Nonnull AppleMidiServerAddress appleMidiServer) {
        int port = appleMidiServer.getPort();
        //System.err.println("onMidiInvitationAccepted(" + String.valueOf(port) + ")");
        if (port == getControlPort())
        {
            //System.err.println("Midi Invitation Accepted - SessionClient Control Port");
            invitePeerAgainViaSession(acceptance);
        } else if (port == getSessionPort()) {
            this.remoteSsrc = acceptance.getSsrc();
            //System.err.println("Midi Invitation Accepted - SessionClient Session Port (LOCAL SSRC " + String.valueOf(ssrc) + " REMOTE SSRC " + String.valueOf(this. remoteSsrc) + ")");
            this.session.addSender(this);
            this.session.onMidiInvitationAccepted(acceptance, appleMidiServer);
            sendClockSync();
        }
        
    }

    public long getCurrentTimestamp()
    {
        final long currentTimestamp = ManagementFactory.getRuntimeMXBean().getUptime() * 10;
        return currentTimestamp;
    }

    public void sendClockSync()
    {
        final long currentTimestamp = getCurrentTimestamp();
        this.lastClockSyncAt = System.currentTimeMillis();
        final AppleMidiClockSynchronization clockSynchronizationRequest =
                    new AppleMidiClockSynchronization(this.ssrc, (byte) 0, currentTimestamp, 0L, 0L);
        try {
            //System.err.println("Sending clock sync CK0");
            send(clockSynchronizationRequest, new AppleMidiServerAddress(this.inetAddress, this.getSessionPort()));
        } catch (final IOException e) {
            log.error("IOException while sending clock synchronization", e);
            e.printStackTrace(System.err);
        }
    }

    @Override
    public void onClockSynchronization(@Nonnull final AppleMidiClockSynchronization clockSynchronization,
                                       @Nonnull final AppleMidiServerAddress appleMidiServer) {
       //System.err.println("Client incoming clock sync! " + String.valueOf(appleMidiServer.getPort()));
       if (clockSynchronization.getCount() == (byte) 1) { // CK1 Sequence
            //System.err.println("Clock CK1");
            final long currentTimestamp = ManagementFactory.getRuntimeMXBean().getUptime() * 10;
            final AppleMidiClockSynchronization clockSynchronizationAnswer =
                    new AppleMidiClockSynchronization(this.ssrc, (byte) 1, clockSynchronization.getTimestamp1(),
                    clockSynchronization.getTimestamp2(), currentTimestamp);
            try {
                send(clockSynchronizationAnswer, appleMidiServer);
            } catch (final IOException e) {
                log.error("IOException while sending clock synchronization", e);
            }
        }
    }

    @Override
    public void onEndSession(@Nonnull final AppleMidiEndSession appleMidiEndSession,
                             @Nonnull final AppleMidiServerAddress appleMidiServer) {
        log.info("Session end from: {}", appleMidiServer);
        this.session.onEndSession(appleMidiEndSession, appleMidiServer);
        this.stopClient();
    }

    @Override
    public void onMidiMessage(final MidiCommandHeader midiCommandHeader, final MidiMessage message,
                              final int timestamp) {
        int inSsrc = midiCommandHeader.getRtpHeader().getSsrc();
        //System.err.println("Midi FROM SSRC "+ String.valueOf(inSsrc));
        if (inSsrc != ssrc)
        {
            this.session.onMidiMessage(midiCommandHeader, message, timestamp);
        }
    }

    /**
     * Add a new {@link AppleMidiSession} to this server
     *
     * @param session The session to be added
     */
    public void setAppleMidiSession(@Nonnull final AppleMidiSession session) {
        this.session = session;
    }

    /**
     * Registers a new {@link SessionChangeListener}
     *
     * @param listener The listener to be registerd
     */
    public void registerSessionChangeListener(@Nonnull final SessionChangeListener listener) {
        sessionChangeListeners.add(listener);
    }

    /**
     * Unregisters a {@link SessionChangeListener}
     *
     * @param listener The listener to be unregisterd
     */
    public void unregisterSessionChangeListener(@Nonnull final SessionChangeListener listener) {
        sessionChangeListeners.remove(listener);
    }

    @Override
    public void sendMidiMessage(@Nonnull MidiMessage message, long timestamp) {
        sequenceNumber++;
        final AppleMidiServerAddress appleMidiServer = new AppleMidiServerAddress(this.inetAddress, this.getSessionPort());
        final long currentTimeIn100Microseconds = this.getCurrentTimestamp();
        final int rtpTimestamp = ((int) currentTimeIn100Microseconds);
        final RtpHeader rtpHeader =
                new RtpHeader((byte) 2, false, false, (byte) 0, false, (byte) 97, sequenceNumber, rtpTimestamp, this.ssrc);
        log.trace("Sending RTP-Header: {}", rtpHeader);
        //System.err.println("Connection Midi FROM "+ String.valueOf(this.ssrc));

        final boolean b = message.getLength() > 15;
        final MidiCommandHeader midiCommandHeader =
                new MidiCommandHeader(b, false, false, false, ((short) message.getLength()), rtpHeader);
        final AppleMidiMessage appleMidiMessage =
                new AppleMidiMessage(midiCommandHeader, Collections.singletonList(new MidiTimestampPair(0, message)));

        try {
            this.send(appleMidiMessage, appleMidiServer);
        } catch (final IOException e) {
            log.error("Error sending MidiMessage to {}", appleMidiServer, e);
            e.printStackTrace(System.err);
        }        
    }

    @Override
    public void onMidiInvitationDeclined(@Nonnull AppleMidiInvitationDeclined decline,
            @Nonnull AppleMidiServerAddress appleMidiServer) {
        System.err.println("Invitation Declined!");
        this.stopClient();
        this.session.onMidiInvitationDeclined(decline, appleMidiServer);
    }

}
