import firebase, {
  analytics,
  auth,
  firestore,
  storage,
  getAuthProvider,
} from '../firebase';

const avatarFileTypes = [
  'image/gif',
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/svg+xml',
];

const authentication = {};

authentication.signUp = fields =>
  new Promise((resolve, reject) => {
    if (!fields) {
      reject();

      return;
    }

    const { firstName } = fields;
    const { lastName } = fields;
    const { username } = fields;
    const { emailAddress } = fields;
    const { password } = fields;

    if (!firstName || !lastName || !username || !emailAddress || !password) {
      reject();
      return;
    }

    const { currentUser } = auth;

    if (currentUser) {
      reject();
      return;
    }

    auth
      .createUserWithEmailAndPassword(emailAddress, password)
      .then(value => {
        const { user } = value;

        if (!user) {
          reject();
          return;
        }

        const { uid } = user;

        if (!uid) {
          reject();
          return;
        }

        const reference = firestore.collection('users').doc(uid);

        if (!reference) {
          reject();

          return;
        }

        reference
          .set({
            firstName,
            lastName,
            username,
          })
          .then(value => {
            analytics.logEvent('sign_up', {
              method: 'password',
            });

            resolve(value);
          })
          .catch(reason => {
            reject(reason);
          });
      })
      .catch(reason => {
        reject(reason);
      });
  });

authentication.signIn = (emailAddress, password) =>
  new Promise((resolve, reject) => {
    if (!emailAddress || !password) {
      reject();

      return;
    }

    const { currentUser } = auth;

    if (currentUser) {
      reject();

      return;
    }

    auth
      .signInWithEmailAndPassword(emailAddress, password)
      .then(value => {
        analytics.logEvent('login', {
          method: 'password',
        });

        resolve(value);
      })
      .catch(reason => {
        reject(reason);
      });
  });

/**
 * Register user using an auth provider
 */
authentication.signInWithAuthProvider = async providerId => {
  const provider = getAuthProvider(providerId);

  const { currentUser } = auth;
  if (currentUser) {
    throw new Error('User already authenticated.');
  }

  // Attempt to register the user
  const response = await auth.signInWithPopup(provider);

  analytics.logEvent('login', {
    method: providerId,
  });

  return response;
};

authentication.linkAuthProvider = providerId =>
  new Promise((resolve, reject) => {
    if (!providerId) {
      reject();

      return;
    }

    const provider = getAuthProvider(providerId);

    if (!provider) {
      reject();

      return;
    }

    const { currentUser } = auth;

    if (!currentUser) {
      reject();

      return;
    }

    currentUser
      .linkWithPopup(provider)
      .then(value => {
        analytics.logEvent('link_auth_provider', {
          value: providerId,
        });

        resolve(value);
      })
      .catch(reason => {
        reject(reason);
      });
  });

authentication.unlinkAuthProvider = providerId =>
  new Promise((resolve, reject) => {
    if (!providerId) {
      reject();

      return;
    }

    const { currentUser } = auth;

    if (!currentUser) {
      reject();

      return;
    }

    currentUser
      .unlink(providerId)
      .then(value => {
        analytics.logEvent('unlink_auth_provider', {
          value: providerId,
        });

        resolve(value);
      })
      .catch(reason => {
        reject(reason);
      });
  });

authentication.authProviderData = providerId => {
  if (!providerId) {
    return;
  }

  const { currentUser } = auth;

  if (!currentUser) {
    return;
  }

  const { providerData } = currentUser;

  if (!providerData) {
    return;
  }

  return providerData.find(
    authProvider => authProvider.providerId === providerId
  );
};

authentication.signOut = () =>
  new Promise((resolve, reject) => {
    const { currentUser } = auth;

    if (!currentUser) {
      reject();

      return;
    }

    auth
      .signOut()
      .then(value => {
        analytics.logEvent('sign_out');

        resolve(value);
      })
      .catch(reason => {
        reject(reason);
      });
  });

authentication.resetPassword = emailAddress =>
  new Promise((resolve, reject) => {
    if (!emailAddress) {
      reject();

      return;
    }

    const { currentUser } = auth;

    if (currentUser) {
      reject();

      return;
    }

    auth
      .sendPasswordResetEmail(emailAddress)
      .then(value => {
        analytics.logEvent('reset_password');

        resolve(value);
      })
      .catch(reason => {
        reject(reason);
      });
  });

authentication.changeAvatar = avatar =>
  new Promise((resolve, reject) => {
    if (!avatar) {
      reject();

      return;
    }

    if (!avatarFileTypes.includes(avatar.type)) {
      reject();

      return;
    }

    if (avatar.size > 20 * 1024 * 1024) {
      reject();

      return;
    }

    const { currentUser } = auth;

    if (!currentUser) {
      reject();

      return;
    }

    const { uid } = currentUser;

    if (!uid) {
      reject();

      return;
    }

    const reference = storage
      .ref()
      .child('images')
      .child('avatars')
      .child(uid);

    if (!reference) {
      reject();

      return;
    }

    reference
      .put(avatar)
      .then(uploadTaskSnapshot => {
        reference
          .getDownloadURL()
          .then(value => {
            currentUser
              .updateProfile({
                photoURL: value,
              })
              .then(value => {
                analytics.logEvent('change_avatar');

                resolve(value);
              })
              .catch(reason => {
                reject(reason);
              });
          })
          .catch(reason => {
            reject(reason);
          });
      })
      .catch(reason => {
        reject(reason);
      });
  });

authentication.removeAvatar = () =>
  new Promise((resolve, reject) => {
    const { currentUser } = auth;

    if (!currentUser) {
      reject();

      return;
    }

    const { uid } = currentUser;

    if (!uid) {
      reject();

      return;
    }

    currentUser
      .updateProfile({
        photoURL: null,
      })
      .then(value => {
        const reference = storage
          .ref()
          .child('images')
          .child('avatars')
          .child(uid);

        if (!reference) {
          reject();

          return;
        }

        reference
          .delete()
          .then(value => {
            analytics.logEvent('remove_avatar');

            resolve(value);
          })
          .catch(reason => {
            reject(reason);
          });
      })
      .catch(reason => {
        reject(reason);
      });
  });

authentication.changeFirstName = firstName =>
  new Promise((resolve, reject) => {
    if (!firstName) {
      reject();

      return;
    }

    const { currentUser } = auth;

    if (!currentUser) {
      reject();

      return;
    }

    const { uid } = currentUser;

    if (!uid) {
      reject();

      return;
    }

    const reference = firestore.collection('users').doc(uid);

    if (!reference) {
      reject();

      return;
    }

    reference
      .update({
        firstName,
      })
      .then(value => {
        analytics.logEvent('change_first_name');

        resolve(value);
      })
      .catch(reason => {
        reject(reason);
      });
  });

authentication.changeLastName = lastName =>
  new Promise((resolve, reject) => {
    if (!lastName) {
      reject();

      return;
    }

    const { currentUser } = auth;

    if (!currentUser) {
      reject();

      return;
    }

    const { uid } = currentUser;

    if (!uid) {
      reject();

      return;
    }

    const reference = firestore.collection('users').doc(uid);

    if (!reference) {
      reject();

      return;
    }

    reference
      .update({
        lastName,
      })
      .then(value => {
        analytics.logEvent('change_last_name');

        resolve(value);
      })
      .catch(reason => {
        reject(reason);
      });
  });

authentication.changeUsername = username =>
  new Promise((resolve, reject) => {
    if (!username) {
      reject();

      return;
    }

    const { currentUser } = auth;

    if (!currentUser) {
      reject();

      return;
    }

    const { uid } = currentUser;

    if (!uid) {
      reject();

      return;
    }

    const reference = firestore.collection('users').doc(uid);

    if (!reference) {
      reject();

      return;
    }

    reference
      .update({
        username,
      })
      .then(value => {
        analytics.logEvent('change_username');

        resolve(value);
      })
      .catch(reason => {
        reject(reason);
      });
  });

authentication.changeEmailAddress = emailAddress =>
  new Promise((resolve, reject) => {
    if (!emailAddress) {
      reject();

      return;
    }

    const { currentUser } = auth;

    if (!currentUser) {
      reject();

      return;
    }

    const { uid } = currentUser;

    if (!uid) {
      reject();

      return;
    }

    currentUser
      .updateEmail(emailAddress)
      .then(value => {
        analytics.logEvent('change_email_address');

        resolve(value);
      })
      .catch(reason => {
        reject(reason);
      });
  });

authentication.changePassword = password =>
  new Promise((resolve, reject) => {
    if (!password) {
      reject();

      return;
    }

    const { currentUser } = auth;

    if (!currentUser) {
      reject();

      return;
    }

    const { uid } = currentUser;

    if (!uid) {
      reject();

      return;
    }

    currentUser
      .updatePassword(password)
      .then(value => {
        const reference = firestore.collection('users').doc(uid);

        if (!reference) {
          reject();

          return;
        }

        reference
          .update({
            lastPasswordChange: firebase.firestore.FieldValue.serverTimestamp(),
          })
          .then(value => {
            analytics.logEvent('change_password');

            resolve(value);
          })
          .catch(reason => {
            reject(reason);
          });
      })
      .catch(reason => {
        reject(reason);
      });
  });

authentication.verifyEmailAddress = () =>
  new Promise((resolve, reject) => {
    const { currentUser } = auth;

    if (!currentUser) {
      reject();

      return;
    }

    currentUser
      .sendEmailVerification()
      .then(value => {
        analytics.logEvent('verify_email_address');

        resolve(value);
      })
      .catch(reason => {
        reject(reason);
      });
  });

authentication.deleteAccount = () =>
  new Promise((resolve, reject) => {
    const { currentUser } = auth;

    if (!currentUser) {
      reject();

      return;
    }

    currentUser
      .delete()
      .then(value => {
        analytics.logEvent('delete_account');

        resolve(value);
      })
      .catch(reason => {
        reject(reason);
      });
  });

export default authentication;
