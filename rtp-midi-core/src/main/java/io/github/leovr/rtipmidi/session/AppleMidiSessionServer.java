package io.github.leovr.rtipmidi.session;

import io.github.leovr.rtipmidi.AppleMidiCommandListener;
import io.github.leovr.rtipmidi.AppleMidiMessageListener;
import io.github.leovr.rtipmidi.AppleMidiServer;
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
import io.github.leovr.rtipmidi.model.AppleMidiServerAddress;
import io.github.leovr.rtipmidi.model.MidiMessage;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;

import javax.annotation.Nonnull;
import java.util.Iterator;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The session server handles MIDI invitation, clock synchronin requests, as well as the MIDI messages. In order to
 * handle MIDI messages a {@link AppleMidiSession} has to be added via {@link #addAppleMidiSession(AppleMidiSession)}.
 * Otherwise all invitation requests are rejected. The session server must be run on a port which is {@code control port
 * + 1}
 */
@Slf4j
public class AppleMidiSessionServer implements AppleMidiCommandListener, AppleMidiMessageListener, Runnable,
        AppleMidiMessageSender {

    private static final int SOCKET_TIMEOUT = 1000;

    private enum State {
        ACCEPT_INVITATIONS, FULL
    }

    private static final int RECEIVE_BUFFER_LENGTH = 1024;
    private final AppleMidiServer server;
    private final ExecutorService executorService;
    private final int ssrc;
    private final String name;
    private final InetAddress inetAddress;
    private final AppleMidiCommandHandler midiCommandHandler = new AppleMidiCommandHandler();
    private final AppleMidiMessageHandler midiMessageHandler = new AppleMidiMessageHandler();
    private final int port;
    private boolean running = true;
    private DatagramSocket socket;
    private final Map<Integer, AppleMidiSessionConnection> currentSessions = new HashMap<>();
    private final List<SessionChangeListener> sessionChangeListeners = new ArrayList<>();
    private Thread thread;

    /**
     * @param name The name under which the other peers should see this server
     * @param port The session server port which must be {@code control port + 1}
     */
    public AppleMidiSessionServer(final InetAddress inetAddress, @Nonnull final String name, final int port, AppleMidiServer server) {
        this(inetAddress, name, port, Executors.newCachedThreadPool(), server);
    }

    AppleMidiSessionServer(final InetAddress inetAddress, @Nonnull final String name, final int port, final ExecutorService executorService, AppleMidiServer server) {
        this.port = port;
        this.ssrc = new Random().nextInt();
        this.name = name;
        this.server = server;
        this.executorService = executorService;
        this.inetAddress = inetAddress;
        midiCommandHandler.registerListener(this);
        midiMessageHandler.registerListener(this);
    }

    Thread createThread(final @Nonnull String name) {
        return new Thread(this, name + "SessionThread");
    }

    public synchronized void start() {
        thread = createThread(name);
        try {
            socket = createSocket();
            socket.setSoTimeout(SOCKET_TIMEOUT);
        } catch (final SocketException e) {
            throw new AppleMidiSessionServerRuntimeException("DatagramSocket cannot be opened", e);
        }
        thread.start();
        log.debug("MIDI session server started");
    }

    DatagramSocket createSocket() throws SocketException {
        return new DatagramSocket(port, this.inetAddress);
    }

    private static String cleanAddress(InetAddress address)
    {
        if (address != null)
        {
            String sAddress = address.toString();
            if (sAddress == null) sAddress = "";
            if (sAddress.startsWith("/"))
                sAddress = sAddress.substring(1);
            return sAddress;
        } else {
            return "";
        }
    }

    public boolean hasConnection(String remoteName, InetAddress address, int port)
    {
        String sAddress = cleanAddress(address);
        Iterator<AppleMidiSessionConnection> connections = currentSessions.values().iterator();
        while(connections.hasNext())
        {
            AppleMidiSessionConnection connection = connections.next();
            AppleMidiServerAddress server = connection.getAppleMidiServerAddress();
            String rAddress = cleanAddress(server.getInetAddress());
            //System.err.println("Comparing " + remoteName + "(" + sAddress + ":"  + String.valueOf(port)+ ") & " + connection.getName()  + "(" + rAddress + ":" + String.valueOf(server.getPort()) + ")");
            if (rAddress.equals(sAddress) && remoteName.equals(connection.getName()))
                return true;
        }
        return false;
    }

    public void closeConnection(InetAddress address, int port)
    {
        AppleMidiSessionConnection conn = null;
        int rSsrc = 0;
        for (final Entry<Integer, AppleMidiSessionConnection> sessionConnection : currentSessions.entrySet())
        {
            AppleMidiServerAddress server = sessionConnection.getValue().getAppleMidiServerAddress();
            if (server.getInetAddress().equals(address) && server.getPort() == port)
            {
                conn = sessionConnection.getValue();
                rSsrc = sessionConnection.getKey();
            }
        }
        if (conn != null)
        {
            try
            {
                AppleMidiServerAddress server = conn.getAppleMidiServerAddress();
                System.err.println("Found Session connection to close " + server.toString());
                AppleMidiEndSession goodbye = new AppleMidiEndSession(2, conn.getInitiatorToken(), rSsrc);
                this.send(goodbye, server);
                onEndSession(goodbye, server);
            } catch (Exception e2) {
                e2.printStackTrace(System.err);
            }
        }
    }


    @Override
    public void run() {
        while (running) {

            try {
                final byte[] receiveData = new byte[RECEIVE_BUFFER_LENGTH];
                final DatagramPacket incomingPacket = new DatagramPacket(receiveData, receiveData.length);
                socket.receive(incomingPacket);
                executorService.execute(new Runnable() {
                    @Override
                    public void run() {
                        if (receiveData[0] == AppleMidiCommand.MIDI_COMMAND_HEADER1) {
                            midiCommandHandler.handle(receiveData,
                                    new AppleMidiServerAddress(incomingPacket.getAddress(), incomingPacket.getPort()));
                        } else {
                            midiMessageHandler.handle(receiveData,
                                    new AppleMidiServerAddress(incomingPacket.getAddress(), incomingPacket.getPort()));
                        }
                    }
                });
            } catch (final SocketTimeoutException ignored) {
            } catch (final IOException e) {
                log.error("IOException while receiving", e);
            }
        }
        socket.close();
    }

    /**
     * Shutds down all sockets and threads
     */
    public void stopServer() {
        running = false;
        currentSessions.clear();
        executorService.shutdown();
        log.debug("MIDI session server stopped");
    }

    private void send(final AppleMidiCommand midiCommand, final AppleMidiServerAddress appleMidiServer) throws IOException {
        send(midiCommand.toByteArray(), appleMidiServer);
    }

    private void send(final byte[] data, final AppleMidiServerAddress appleMidiServer) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("Sending data {} to server {}", Hex.encodeHexString(data), appleMidiServer);
        }
        socket.send(new DatagramPacket(data, data.length, appleMidiServer.getInetAddress(), appleMidiServer.getPort()));
    }

    @Override
    public void send(@Nonnull final AppleMidiMessage appleMidiMessage,
                     @Nonnull final AppleMidiServerAddress appleMidiServer) throws IOException {
        send(appleMidiMessage.toByteArray(), appleMidiServer);
    }

    @Override
    public void onMidiInvitation(@Nonnull final AppleMidiInvitationRequest invitation,
                                 @Nonnull final AppleMidiServerAddress appleMidiServer) {
        log.info("MIDI invitation from: {}", appleMidiServer);
        if (getSessionServerState() == State.ACCEPT_INVITATIONS) {
            sendMidiInvitationAnswer(appleMidiServer, "accept",
                    new AppleMidiInvitationAccepted(invitation.getProtocolVersion(), invitation.getInitiatorToken(),
                            ssrc, name));
            final AppleMidiSessionConnection connection =
                    new AppleMidiSessionConnection(server.getAppleMidiSession(), appleMidiServer, ssrc, this);
            connection.setInitiatorToken(invitation.getInitiatorToken());
            connection.setName(invitation.getName());
            server.getAppleMidiSession().addSender(connection);
            currentSessions.put(invitation.getSsrc(), connection);
        } else {
            sendMidiInvitationAnswer(appleMidiServer, "decline",
                    new AppleMidiInvitationDeclined(invitation.getProtocolVersion(), invitation.getInitiatorToken(),
                            ssrc, name));
        }
    }

    @Override
    public void onMidiInvitationAccepted(@Nonnull AppleMidiInvitationAccepted acceptance,
            @Nonnull AppleMidiServerAddress appleMidiServer) {
        System.err.println("Midi Invitation Accepted - SessionServer");
    }

    /**
     * @return {@link State#FULL} if no sessions are available. {@link State#ACCEPT_INVITATIONS} otherwise
     */
    private State getSessionServerState() {
        return server.getAppleMidiSession() == null ? State.FULL : State.ACCEPT_INVITATIONS;
    }

    private void sendMidiInvitationAnswer(final AppleMidiServerAddress appleMidiServer, final String type,
                                          final AppleMidiInvitation midiInvitation) {
        try {
            log.info("Sending invitation {} to: {}", type, appleMidiServer);
            send(midiInvitation, appleMidiServer);
        } catch (final IOException e) {
            log.error("IOException while sending invitation {}", type, e);
        }
    }

    @Override
    public void onClockSynchronization(@Nonnull final AppleMidiClockSynchronization clockSynchronization,
                                       @Nonnull final AppleMidiServerAddress appleMidiServer) {
        if (clockSynchronization.getCount() == (byte) 0) { // CK0 Sequence
            final AppleMidiSessionConnection sessionTuple = currentSessions.get(clockSynchronization.getSsrc());
            final long currentTimestamp;
            if (sessionTuple != null) {
                final long sessionTimestamp = sessionTuple.getAppleMidiSession().getCurrentTimestamp();
                if (sessionTimestamp != -1) {
                    currentTimestamp = sessionTimestamp;
                } else {
                    currentTimestamp = getFallbackTimestamp();
                }
            } else {
                currentTimestamp = getFallbackTimestamp();
            }
            log.debug("Answering with timestamp: {}", currentTimestamp);
            final AppleMidiClockSynchronization clockSynchronizationAnswer =
                    new AppleMidiClockSynchronization(ssrc, (byte) 1, clockSynchronization.getTimestamp1(),
                            currentTimestamp, 0L);
            try {
                send(clockSynchronizationAnswer, appleMidiServer);
            } catch (final IOException e) {
                log.error("IOException while sending clock synchronization", e);
            }
        } else if (clockSynchronization.getCount() == (byte) 2) { // CK2 Sequence
            final long offsetEstimate =
                    (clockSynchronization.getTimestamp3() + clockSynchronization.getTimestamp1()) / 2 -
                            clockSynchronization.getTimestamp2();

            final AppleMidiSessionConnection midiServer = currentSessions.get(clockSynchronization.getSsrc());
            if (midiServer != null) {
                midiServer.getAppleMidiSession().setOffsetEstimate(offsetEstimate);
            }
        }
    }

    private long getFallbackTimestamp() {
        return ManagementFactory.getRuntimeMXBean().getUptime() * 10;
    }

    @Override
    public void onEndSession(@Nonnull final AppleMidiEndSession appleMidiEndSession,
                             @Nonnull final AppleMidiServerAddress appleMidiServer) {
        log.info("Session end from: {}", appleMidiServer);
        final AppleMidiSessionConnection midiServer = currentSessions.get(appleMidiEndSession.getSsrc());
        if (midiServer != null) {
            final AppleMidiSession appleMidiSession = midiServer.getAppleMidiSession();
            appleMidiSession.removeSender(midiServer);
            appleMidiSession.onEndSession(appleMidiEndSession, appleMidiServer);
        }
        final AppleMidiSessionConnection sessionTuple = currentSessions.remove(appleMidiEndSession.getSsrc());
        if (sessionTuple != null) {
            System.err.println("sessionTuple Removed");
        }
    }

    @Override
    public void onMidiMessage(final MidiCommandHeader midiCommandHeader, final MidiMessage message,
                              final int timestamp) {
        final AppleMidiSessionConnection sessionTuple = currentSessions.get(midiCommandHeader.getRtpHeader().getSsrc());
        if (sessionTuple != null) {
            sessionTuple.getAppleMidiSession().onMidiMessage(midiCommandHeader, message, timestamp);
        } else {
            log.debug("Could not find session for ssrc: {}", ssrc);
        }
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
    public void onMidiInvitationDeclined(@Nonnull AppleMidiInvitationDeclined decline,
            @Nonnull AppleMidiServerAddress appleMidiServer) {
        // TODO Auto-generated method stub
        
    }

    

}
