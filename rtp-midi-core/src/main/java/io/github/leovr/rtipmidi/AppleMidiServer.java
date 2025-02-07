package io.github.leovr.rtipmidi;

import io.github.leovr.rtipmidi.session.AppleMidiSession;
import io.github.leovr.rtipmidi.session.AppleMidiSessionClient;
import io.github.leovr.rtipmidi.session.SessionChangeListener;
import io.github.leovr.rtipmidi.control.AppleMidiControlServer;
import io.github.leovr.rtipmidi.session.AppleMidiSessionServer;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

import javax.annotation.Nonnull;

/**
 * Main class for the RTP MIDI communication. This class instantiates the {@link AppleMidiControlServer} and the {@link
 * AppleMidiSessionServer}. In order to receive midi messages a {@link AppleMidiSession} should be registerd via {@link
 * #addAppleMidiSession(AppleMidiSession)}.
 */
@Slf4j
public class AppleMidiServer implements SessionChangeListener {

    private static final int DEFAULT_PORT = 50004;
    private static final String DEFAULT_NAME = "rtpMIDIJava";
    @Getter
    private final int port;
    private final AppleMidiControlServer controlServer;
    private final AppleMidiSessionServer sessionServer;
    private final ArrayList<AppleMidiSessionClient> clients;
    private AppleMidiSession session;
    private String name;

    /**
     * Creates a {@link AppleMidiServer} with {@link #DEFAULT_NAME} and {@link #DEFAULT_PORT}
     * @throws UnknownHostException
     */
    public AppleMidiServer() throws UnknownHostException {
        this(InetAddress.getLocalHost(), DEFAULT_NAME, DEFAULT_PORT);
    }

    /**
     * Creates a new {@link AppleMidiServer} with the given name and port
     *
     * @param name The name under which the other peers should see this server
     * @param port The control port. A session server will be created on the {@code port + 1}
     */
    public AppleMidiServer(final InetAddress socketAddress, @Nonnull final String name, final int port) {
        this.port = port;
        this.name = name;
        this.clients = new ArrayList<AppleMidiSessionClient>();
        controlServer = new AppleMidiControlServer(socketAddress, name, port);
        sessionServer = new AppleMidiSessionServer(socketAddress, name, port + 1, this);
        sessionServer.registerSessionChangeListener(this);
        controlServer.registerEndSessionListener(sessionServer);
    }

    public AppleMidiSessionClient connect(@Nonnull String remoteName, InetAddress address, int port)
    {
        AppleMidiSessionClient client = new AppleMidiSessionClient(remoteName, address, port, this.name);
        this.clients.add(client);
        return client;
    }

    public boolean hasConnection(String remoteName, InetAddress address, int port)
    {
        return this.sessionServer.hasConnection(remoteName, address, port);
    }

    public void closeConnection(InetAddress address, int port)
    {
        this.controlServer.closeConnection(address, port);
        this.sessionServer.closeConnection(address, port+1);
    }

    /**
     * Add a new {@link AppleMidiSession} to this server
     *
     * @param session The session to be added
     */
    public void setAppleMidiSession(@Nonnull final AppleMidiSession session) {
        this.session = session;
    }

    public AppleMidiSession getAppleMidiSession()
    {
        return this.session;
    }

    @Override
    public void onMaxNumberOfSessionsChange(final int maxNumberOfSessions) {
        controlServer.setMaxNumberOfSessions(maxNumberOfSessions);
    }

    /**
     * Starts the control server and the session server
     */
    public void start() {
        sessionServer.start();
        controlServer.start();
        log.info("AppleMidiServer started");
    }

    /**
     * Stops the session server and the control server
     */
    public void stop() {
        sessionServer.stopServer();
        controlServer.stopServer();
        log.info("AppleMidiServer stopped");
    }

}
