import firebase, {
  analytics,
  auth,
  firestore,
  storage,
  getAuthProvider,
  COLLECTIONS,
  ANALYTICS_EVENTS,
  AUTH_METHODS,
} from '../firebase';

const avatarFileTypes = [
  'image/gif',
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/svg+xml',
];

const authentication = {};

/**
 * Register an email and password user
 */
authentication.signUp = async fields => {
  if (!fields) {
    return;
  }

  const { firstName, lastName, username, emailAddress, password } = fields;

  if (!firstName || !lastName || !username || !emailAddress || !password) {
    return;
  }

  const response = await auth.createUserWithEmailAndPassword(
    emailAddress,
    password
  );

  const {
    user: { uid },
  } = response;

  const reference = firestore.collection(COLLECTIONS.USERS).doc(uid);

  const userProfile = await reference.set({
    firstName,
    lastName,
    username,
  });

  analytics.logEvent(ANALYTICS_EVENTS.SIGNUP, {
    method: AUTH_METHODS.PASSWORD,
  });

  return userProfile;
};

/**
 * Authenticate email/password user
 */
authentication.signIn = async (emailAddress, password) => {
  if (!emailAddress || !password) {
    return;
  }

  const response = await auth.signInWithEmailAndPassword(
    emailAddress,
    password
  );

  analytics.logEvent(ANALYTICS_EVENTS.LOGIN, {
    method: AUTH_METHODS.PASSWORD,
  });
  return response;
};

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

  analytics.logEvent(ANALYTICS_EVENTS.LOGIN, {
    method: providerId,
  });

  return response;
};

/**
 * Link a user with an auth provider
 */
authentication.linkAuthProvider = async providerId => {
  const provider = getAuthProvider(providerId);

  const { currentUser } = auth;

  if (!currentUser) {
    throw new Error('User is not authenticated');
  }

  const response = await currentUser.linkWithPopup(provider);

  analytics.logEvent(ANALYTICS_EVENTS.LINK_AUTH_PROVIDER, {
    value: providerId,
  });

  return response;
};

/**
 * Unlink auth provider from user
 */
authentication.unlinkAuthProvider = async providerId => {
  const { currentUser } = auth;
  if (!currentUser) {
    throw new Error('User is not authenticated');
  }

  const response = await currentUser.unlink(providerId);

  analytics.logEvent('unlink_auth_provider', {
    value: providerId,
  });

  return response;
};

/**
 * Get the current users provider data for a specific provider
 */
authentication.authProviderData = providerId => {
  const { currentUser, currentUser: { providerData } = {} } = auth;
  if (!currentUser) {
    throw new Error('User is not authenticated');
  }

  return providerData.find(
    authProvider => authProvider.providerId === providerId
  );
};

/** Signout a user */
authentication.signOut = async () => {
  const { currentUser } = auth;

  if (!currentUser) {
    return;
  }

  await auth.signOut();
  analytics.logEvent(ANALYTICS_EVENTS.LOGOUT);
};

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
