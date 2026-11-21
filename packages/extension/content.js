// OpenPoD Content Script
// Injects helper bridge into web pages so web agents can fetch PoD delegation proofs
window.addEventListener('message', async (event) => {
  if (event.data && event.data.type === 'REQUEST_POD_DELEGATION') {
    const origin = window.location.origin;
    chrome.runtime.sendMessage(
      { type: 'GET_POD_TOKEN', targetOrigin: origin, scope: event.data.scope },
      (response) => {
        window.postMessage({
          type: 'RESPONSE_POD_DELEGATION',
          id: event.data.id,
          response
        }, '*');
      }
    );
  }
});
