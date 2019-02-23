// Example program by Cody W. Eilar 
// cody.eilar@gmail.com
var createNoise = require('noise-c.wasm');

createNoise(function (noise) {

  // Helper function to get constants values: 
  function getAction(a) {
    return Object.keys(noise.constants).filter(key => noise.constants[key] == a)[0]
  } 
  // Client/Phone/Laptop -  the initiator
  // Device - The responder
  // 
  // Initiator knows the responders public key
  // The responder doesn't know the initiator's key
  //
  // Most useful pattern = 'XK' for first connection.
  //  - X => Static key for initiator is transmitted to responder
  //  - K => Static key for the responder is known to the initiator
  //
  // Most useful conneciton after first connection is made 'KK' 
  // - K => Static key for initiator is known to responder (because of previous
  // step) 
  // - K  => Static key for responder known to initiator

  // 1. 
  let pattern = 'XK'
  let curve = '25519'
  let curve_id = noise.constants.NOISE_DH_CURVE25519
  let cipher = 'ChaChaPoly' 
  let hash = 'BLAKE2b' 
  let protocol_name = `Noise_${pattern}_${curve}_${cipher}_${hash}`
  console.log(`Using protocol: ${protocol_name} `) 
  
  // Setup the keys
  let [initiator_private, initiator_public] = noise.CreateKeyPair(curve_id) 
  let [responder_private, responder_public] = noise.CreateKeyPair(curve_id) 
  console.log("Initiator public key = ", Buffer.from(initiator_public).toString('hex')  ) 
  console.log("Responder public key = ", Buffer.from(responder_public).toString('hex')  ) 

  // Setup the handshake 
  let initiator_hs = noise.HandshakeState(protocol_name, noise.constants.NOISE_ROLE_INITIATOR)
  let responder_hs = noise.HandshakeState(protocol_name, noise.constants.NOISE_ROLE_RESPONDER)

  // Initialize 
  // Preshare data so man-in-the middle is less likely. Both ends must have this
  // data identical.  Not required though
  let prologue = null 
  // There is an ability to use a pre-shared key mechanism as well. But in this
  // use case are not going to use it. 
  let psk = null
  initiator_hs.Initialize(prologue, initiator_private, responder_public, psk) 
  // Note: In the scenario I've defined above, we assuming that we don't know
  // the public key of the initiator, hence why the responder doesn't have it! 
  responder_hs.Initialize(prologue, responder_private, null /*public key of initiator for mutual auth*/, psk) 

  // perform the handshake. We know we are ready to start communicaiton once 
  // both the intiator and the responder are in the split state! 
  let ready = false
  let msgToResponder
  let msgToInitiator
  while(initiator_hs.GetAction != noise.constants.NOISE_ACTION_SPLIT && responder_hs.GetAction() != noise.constants.NOISE_ACTION_SPLIT) {
    switch(initiator_hs.GetAction()) 
    {
      case noise.constants.NOISE_ACTION_WRITE_MESSAGE: 
        console.log('Initiator writing message to responder..') 
        msgToResponder = initiator_hs.WriteMessage() 
        break; 
      case noise.constants.NOISE_ACTION_READ_MESSAGE: 
        console.log('Initiator reading message from responder...') 
        if (msgToInitiator) {
          initiator_hs.ReadMessage(msgToInitiator, true) 
          msgToInitiator = null
        } 
        break; 
    } 
    switch(responder_hs.GetAction()) 
    {
      case noise.constants.NOISE_ACTION_WRITE_MESSAGE: 
        console.log('Responder writing message to initiator..') 
        msgToInitiator = responder_hs.WriteMessage() 
        break; 
      case noise.constants.NOISE_ACTION_READ_MESSAGE: 
        console.log('Responder reading message from initiator...') 
        if (msgToResponder) {
          responder_hs.ReadMessage(msgToResponder, true) 
          msgToResponder = null
         }
        break; 
    } 
  } 

  // At this point, we are ready to split and start sending messages. 
  // The key here is to understand that we need to get everything into the split
  // state. 

  // Ready to split and start sending messages 
  let [initiator_send, initiator_receive]	= initiator_hs.Split()
  let [responder_send, responder_receive]	= responder_hs.Split()

  // Initiator is going to send message
  let ad = new Uint8Array()
  let messageToResponder = Uint8Array.from(Buffer.from("Hiya Responder!"))
  let cipherToResponder = initiator_send.EncryptWithAd(ad, messageToResponder)  
  let messageFromInitiator = responder_receive.DecryptWithAd(ad, cipherToResponder)
  console.log('Decrypted message received by the responder: ', Buffer.from(messageFromInitiator).toString() )

  let messageToInitiator = Uint8Array.from(Buffer.from("Well hello, initiator!"))
  let cipherToInitiator = responder_send.EncryptWithAd(ad, messageToInitiator)
  let messageFromResponder = initiator_receive.DecryptWithAd(ad, cipherToInitiator)
  console.log('Decrypted message received by the initiator: ', Buffer.from(messageFromResponder).toString())

});
