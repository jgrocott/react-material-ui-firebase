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
  analytics.logEvent(ANALYTICS_EVENTS.SIGNOUT);
};

/**
 * Request a password reset.
 */
authentication.resetPassword = async emailAddress => {
  if (!emailAddress) {
    return;
  }

  const { currentUser } = auth;

  if (!currentUser) {
    throw new Error('User is not authenticated');
  }

  const response = await auth.sendPasswordResetEmail(emailAddress);
  analytics.logEvent(ANALYTICS_EVENTS.RESET_PASSWORD);

  return response;
};

/**
 * Change a users avatar
 */
authentication.changeAvatar = async avatar => {
  if (!avatarFileTypes.includes(avatar.type)) {
    throw new Error('Invalid file type specified.');
  }

  if (avatar.size > 20 * 1024 * 1024) {
    throw new Error('Maximum file size exceeded.');
  }

  const {
    currentUser,
    currentUser: { uid },
  } = auth;

  if (!currentUser) {
    throw new Error('User is not authenticated');
  }

  const reference = storage
    .ref()
    .child(COLLECTIONS.IMAGES)
    .child(COLLECTIONS.AVATARS)
    .child(uid);

  await reference.put(avatar);
  const downloadURL = await reference.getDownloadURL();

  await currentUser.updateProfile({
    photoURL: downloadURL,
  });

  analytics.logEvent(ANALYTICS_EVENTS.CHANGE_AVATAR);
};

/**
 * Remove a users avatar
 */
authentication.removeAvatar = async () => {
  const {
    currentUser,
    currentUser: { uid },
  } = auth;

  if (!currentUser) {
    throw new Error('User is not authenticated');
  }

  await currentUser.updateProfile({
    photoURL: null,
  });

  const reference = storage
    .ref()
    .child(COLLECTIONS.IMAGES)
    .child(COLLECTIONS.AVATARS)
    .child(uid);

  await reference.delete();

  analytics.logEvent(ANALYTICS_EVENTS.REMOVE_AVATAR);
};

/**
 * Change a users first name
 */
authentication.changeFirstName = async firstName => {
  if (!firstName) {
    throw new Error('First name is required.');
  }

  const {
    currentUser,
    currentUser: { uid },
  } = auth;

  if (!currentUser) {
    throw new Error('User is not authenticated');
  }

  const reference = firestore.collection(COLLECTIONS.USERS).doc(uid);

  await reference.update({
    firstName,
  });

  analytics.logEvent(ANALYTICS_EVENTS.CHANGE_FIRST_NAME);
};

/**
 * Change a users last name
 */
authentication.changeLastName = async lastName => {
  if (!lastName) {
    throw new Error('Last name is required.');
  }

  const {
    currentUser,
    currentUser: { uid },
  } = auth;

  if (!currentUser) {
    throw new Error('User is not authenticated');
  }

  const reference = firestore.collection(COLLECTIONS.USERS).doc(uid);

  await reference.update({
    lastName,
  });

  analytics.logEvent(ANALYTICS_EVENTS.CHANGE_LAST_NAME);
};

/**
 * Change a users username
 */
authentication.changeUsername = async username => {
  if (!username) {
    throw new Error('Username is required.');
  }

  const {
    currentUser,
    currentUser: { uid },
  } = auth;

  if (!currentUser) {
    throw new Error('User is not authenticated');
  }

  const reference = firestore.collection(COLLECTIONS.USERS).doc(uid);

  await reference.update({
    username,
  });

  analytics.logEvent(ANALYTICS_EVENTS.CHANGE_USERNAME);
};

/**
 * Change a users email address
 */
authentication.changeEmailAddress = async emailAddress => {
  if (!emailAddress) {
    throw new Error('Email address is required.');
  }

  const { currentUser } = auth;

  if (!currentUser) {
    throw new Error('User is not authenticated');
  }

  await currentUser.updateEmail(emailAddress);

  analytics.logEvent(ANALYTICS_EVENTS.CHANGE_EMAIL_ADDRESS);
};

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
