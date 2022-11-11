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
import io.github.leovr.rtipmidi.model.AppleMidiServer;
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
        AppleMidiMessageSender {

    private static final int SOCKET_TIMEOUT = 1000;
    private static final int RECEIVE_BUFFER_LENGTH = 1024;

    private final ExecutorService executorService;
    private final int ssrc;
    private int remoteSsrc;
    private final String name;
    private final InetAddress inetAddress;
    private final int port;
    private final AppleMidiCommandHandler midiCommandHandler = new AppleMidiCommandHandler();
    private final AppleMidiMessageHandler midiMessageHandler = new AppleMidiMessageHandler();
    private boolean running = true;
    private DatagramSocket controlSocket;
    private DatagramSocket sessionSocket;
    private AppleMidiSession session;
    private AppleMidiSessionConnection outboundSessionConnection;
    private final List<SessionChangeListener> sessionChangeListeners = new ArrayList<>();
    private Thread controlThread;
    private Thread sessionThread;
    private long lastClockSyncAt;

    /**
     * @param name The name under which the other peers should see this server
     * @param port The session server port which must be {@code control port + 1}
     */
    public AppleMidiSessionClient(final InetAddress inetAddress, final int port, @Nonnull final String name) {
        this(inetAddress, port, name, Executors.newCachedThreadPool());
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

    AppleMidiSessionClient(final InetAddress inetAddress, final int port, @Nonnull final String name, final ExecutorService executorService) {
        this.port = port;
        this.ssrc = createSsrc(name);
        this.name = name;
        this.executorService = executorService;
        this.inetAddress = inetAddress;
        midiCommandHandler.registerListener(this);
        midiMessageHandler.registerListener(this);
    }

    public synchronized void start() {
        this.controlThread = new Thread(this.controlRunnable, name + ".control");
        this.sessionThread = new Thread(this.sessionRunnable, name + ".session");
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
        AppleMidiInvitationRequest invitation = new AppleMidiInvitationRequest(2, getNewInitiatorToken(), this.ssrc, this.name);
        try
        {
            sendControl(invitation);
            System.err.println("Sent invitation!");
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
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
                                System.err.println("INCOMING CONTROL COMMAND PACKET");
                                midiCommandHandler.handle(receiveDataControl,
                                        new AppleMidiServer(incomingPacketControl.getAddress(), incomingPacketControl.getPort()));
                            } else {
                                midiMessageHandler.handle(receiveDataControl,
                                        new AppleMidiServer(incomingPacketControl.getAddress(), incomingPacketControl.getPort()));
                            }
                        }
                    });

                } catch (final SocketTimeoutException ignored) {
                } catch (final IOException e) {
                    log.error("IOException while receiving", e);
                }
                if ((System.currentTimeMillis() - AppleMidiSessionClient.this.lastClockSyncAt) > 10000 && AppleMidiSessionClient.this.lastClockSyncAt != 0)
                {
                    sendClockSync();
                }
            }
            controlSocket.close();
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
                                System.err.println("INCOMING SESSION COMMAND PACKET");
                                midiCommandHandler.handle(receiveDataSession,
                                        new AppleMidiServer(incomingPacketSession.getAddress(), incomingPacketSession.getPort()));
                            } else {
                                midiMessageHandler.handle(receiveDataSession,
                                        new AppleMidiServer(incomingPacketSession.getAddress(), incomingPacketSession.getPort()));
                            }
                        }
                    });
                } catch (final SocketTimeoutException ignored) {
                } catch (final IOException e) {
                    log.error("IOException while receiving", e);
                }
            }
            sessionSocket.close();
        }
    };

    public void invitePeerAgainViaSession(AppleMidiInvitationAccepted acceptance)
    {
        System.err.println("Invite peer again");
        AppleMidiServer outgoingServer = new AppleMidiServer(this.inetAddress, getSessionPort());
        AppleMidiInvitationRequest invitation = new AppleMidiInvitationRequest(2, acceptance.getInitiatorToken(), this.ssrc, this.name);
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
    public void stopServer() {
        running = false;
        outboundSessionConnection = null;
        executorService.shutdown();
        log.debug("MIDI session server stopped");
    }

    private void sendControl(final AppleMidiCommand midiCommand) throws IOException {
        sendControl(midiCommand.toByteArray());
    }

    private void sendControl(final byte[] data) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("Sending data {} to server {}", Hex.encodeHexString(data));
        }
        System.err.println("Sending Control Packet to " + this.inetAddress.toString() + ":" + String.valueOf(this.port));
        controlSocket.send(new DatagramPacket(data, data.length, this.inetAddress, this.getControlPort()));
    }

    public void sendControl(@Nonnull final AppleMidiMessage appleMidiMessage) throws IOException {
        sendControl(appleMidiMessage.toByteArray());
    }

    private void send(final AppleMidiCommand midiCommand, final AppleMidiServer appleMidiServer) throws IOException {
        send(midiCommand.toByteArray(), appleMidiServer);
    }

    private void send(final byte[] data, final AppleMidiServer appleMidiServer) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("Sending data {} to server {}", Hex.encodeHexString(data), appleMidiServer);
        }
        sessionSocket.send(new DatagramPacket(data, data.length, this.inetAddress, this.getSessionPort()));
    }

    @Override
    public void send(@Nonnull final AppleMidiMessage appleMidiMessage,
                     @Nonnull final AppleMidiServer appleMidiServer) throws IOException {

        System.err.println("SENDING SESSION MIDI DATAGRAM " + String.valueOf(appleMidiServer.getPort()));
        send(appleMidiMessage.toByteArray(), appleMidiServer);
    }

    @Override
    public void onMidiInvitation(@Nonnull final AppleMidiInvitationRequest invitation,
                                 @Nonnull final AppleMidiServer appleMidiServer) {
        
    }

    @Override
    public void onMidiInvitationAccepted(@Nonnull AppleMidiInvitationAccepted acceptance,
            @Nonnull AppleMidiServer appleMidiServer) {
        int port = appleMidiServer.getPort();
        System.err.println("onMidiInvitationAccepted(" + String.valueOf(port) + ")");
        if (port == getControlPort())
        {
            System.err.println("Midi Invitation Accepted - SessionClient Control Port");
            invitePeerAgainViaSession(acceptance);
        } else if (port == getSessionPort()) {
            this.remoteSsrc = acceptance.getSsrc();
            System.err.println("Midi Invitation Accepted - SessionClient Session Port (LOCAL SSRC " + String.valueOf(ssrc) + " REMOTE SSRC " + String.valueOf(this. remoteSsrc) + ")");
            this.outboundSessionConnection = new AppleMidiSessionConnection(this.session, appleMidiServer, this.ssrc, this);
            this.session.addSender(this.outboundSessionConnection);
            sendClockSync();
        }
        
    }

    public void sendClockSync()
    {
        this.lastClockSyncAt = System.currentTimeMillis();
        final long currentTimestamp = ManagementFactory.getRuntimeMXBean().getUptime() * 10;
        final AppleMidiClockSynchronization clockSynchronizationRequest =
                    new AppleMidiClockSynchronization(this.ssrc, (byte) 0, currentTimestamp, 0L, 0L);
        try {
            System.err.println("Sending clock sync CK0");
            send(clockSynchronizationRequest, this.outboundSessionConnection.getAppleMidiServer());
        } catch (final IOException e) {
            log.error("IOException while sending clock synchronization", e);
            e.printStackTrace(System.err);
        }
    }

    @Override
    public void onClockSynchronization(@Nonnull final AppleMidiClockSynchronization clockSynchronization,
                                       @Nonnull final AppleMidiServer appleMidiServer) {
       System.err.println("Client incoming clock sync! " + String.valueOf(appleMidiServer.getPort()));
       if (clockSynchronization.getCount() == (byte) 1) { // CK1 Sequence
            System.err.println("Clock CK1");
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
                             @Nonnull final AppleMidiServer appleMidiServer) {
        log.info("Session end from: {}", appleMidiServer);
        if (this.outboundSessionConnection != null) {
            final AppleMidiSession appleMidiSession = this.outboundSessionConnection.getAppleMidiSession();
            appleMidiSession.removeSender(this.outboundSessionConnection);
            appleMidiSession.onEndSession(appleMidiEndSession, appleMidiServer);
        }
    }

    @Override
    public void onMidiMessage(final MidiCommandHeader midiCommandHeader, final MidiMessage message,
                              final int timestamp) {
        int inSsrc = midiCommandHeader.getRtpHeader().getSsrc();
        System.err.println("Midi FROM SSRC "+ String.valueOf(inSsrc));
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

}
