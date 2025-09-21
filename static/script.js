function copyLink(inputId) {
    const input = document.getElementById(inputId);
    input.select();
    document.execCommand('copy');
    alert('Link copied to clipboard!');
}

function showMessage(message, messageId) {
    const modal = document.getElementById('message-modal');
    const modalMessage = document.getElementById('modal-message');
    const markReadLink = document.getElementById('modal-mark-read');
    const deleteLink = document.getElementById('modal-delete');
    
    modalMessage.textContent = message;
    markReadLink.href = `/mark_read/${USER_ID}/${messageId}`;
    deleteLink.href = `/delete/${USER_ID}/${messageId}`;
    modal.classList.remove('hidden');
}

function closeModal() {
    const modal = document.getElementById('message-modal');
    modal.classList.add('hidden');
}

// Push notification subscription
document.addEventListener('DOMContentLoaded', () => {
    const enableNotificationsButton = document.getElementById('enable-notifications');
    
    if (enableNotificationsButton) {
        enableNotificationsButton.addEventListener('click', () => {
            if ('serviceWorker' in navigator && 'PushManager' in window) {
                navigator.serviceWorker.register('/static/service-worker.js')
                    .then(registration => {
                        return registration.pushManager.subscribe({
                            userVisibleOnly: true,
                            applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY)
                        });
                    })
                    .then(subscription => {
                        return fetch(`/subscribe/${USER_ID}`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ subscription })
                        });
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert('Push notifications enabled!');
                            enableNotificationsButton.disabled = true;
                            enableNotificationsButton.textContent = '🔔 Notifications Enabled';
                        } else {
                            alert('Failed to enable notifications: ' + data.error);
                        }
                    })
                    .catch(error => {
                        console.error('Error enabling notifications:', error);
                        alert('Failed to enable notifications');
                    });
            } else {
                alert('Push notifications are not supported in this browser');
            }
        });
    }
});

function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding)
        .replace(/\-/g, '+')
        .replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}