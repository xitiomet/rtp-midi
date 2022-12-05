[![Build Status](https://travis-ci.org/LeovR/rtp-midi.svg?branch=master)](https://travis-ci.org/LeovR/rtp-midi)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.leovr/rtp-midi/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.github.leovr/rtp-midi)
# rtpmidi
A Java implementation of the RTP-MIDI protocol. 

## Usage

Currently this library can only be used as a RTP-MIDI session listener.

1. Create a `AppleMidiServer`
2. Add a `AppleMidiSession` to the server
  * Either a `MidiDeviceAppleMidiSession` if a `MidiDevice` should be used
  * Or a `MidiReceiverAppleMidiSession` if only a `Receiver` interface should be used. E.g. for direct processing of messages without a `MidiDevice`.
3. `start()` the server

To announce the server via Apple's bonjour the [jMDNS](https://github.com/jmdns/jmdns) library can be used.

###Demo Server

    public class Application {
    
        public static void main(final String[] args) throws InterruptedException {
            try {
                JmDNS jmdns = JmDNS.create(InetAddress.getLocalHost());
    
                ServiceInfo serviceInfo =
                        ServiceInfo.create("_apple-midi._udp.local.", "rtpMidiJava", 50004, "apple-midi");
                jmdns.registerService(serviceInfo);

                MidiDevice midiDevice = ;//get MIDI device

                AppleMidiServer server = new AppleMidiServer();
                server.addAppleMidiSession(
                                new MidiDeviceAppleMidiSession(new MidiDeviceModePair(midiDevice, MidiDeviceMode.READ_ONLY)));

                server.start();

                System.in.read();

                server.stop();
            } catch (final IOException e) {
                e.printStackTrace();
            }
        }
    }

###Demo Client (Implemented by @xitiomet)

    public class Application {
    
        public static void main(final String[] args) throws InterruptedException {
            try {

                // Same session can be used for client and server. new methods added "onMidiInvitationAccepted" and "onMidiInvitationDeclined"
                AppleMidiSession session = new AppleMidiSession()
                {
                    protected void onMidiMessage(final io.github.leovr.rtipmidi.model.MidiMessage message, final long timestamp)
                    {
                        
                    }

                    protected void onMidiInvitation(AppleMidiInvitationRequest req, AppleMidiServer server)
                    {
                        System.err.println("RTP Invitation from " + req.getName());
                    }

                    @Override
                    public void onMidiInvitationAccepted(@Nonnull AppleMidiInvitationAccepted arg0,
                            @Nonnull io.github.leovr.rtipmidi.model.AppleMidiServer arg1) {
                        System.err.println("RTP Invitation accepted by " + arg0.getName());

                        
                    }

                    @Override
                    public void onMidiInvitationDeclined(@Nonnull AppleMidiInvitationDeclined arg0,
                            @Nonnull io.github.leovr.rtipmidi.model.AppleMidiServer arg1) {
                        System.err.println("RTP Invitation declined by " + arg0.getName());
                    }
                AppleMidiSessionClient client = new AppleMidiSessionClient("Remote Server Name", InetAddress.getByName(ipAddress), 5004, "Local Server Name");
                client.setAppleMidiSession(session);
                client.start();
            } catch (final IOException e) {
                e.printStackTrace();
            }
        }
    }


## ToDo
* Implement journaling
* Implement missing session protocol commands
