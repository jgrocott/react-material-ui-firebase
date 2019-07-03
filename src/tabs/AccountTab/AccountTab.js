import React, { Component } from 'react';

import PropTypes from 'prop-types';

import { withStyles } from '@material-ui/core/styles';

import DialogContent from '@material-ui/core/DialogContent';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import CircularProgress from '@material-ui/core/CircularProgress';
import Box from '@material-ui/core/Box';
import Avatar from '@material-ui/core/Avatar';
import Button from '@material-ui/core/Button';

import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';

import Hidden from '@material-ui/core/Hidden';
import TextField from '@material-ui/core/TextField';
import Tooltip from '@material-ui/core/Tooltip';
import IconButton from '@material-ui/core/IconButton';

import PortraitIcon from '@material-ui/icons/Portrait';
import CloudUploadIcon from '@material-ui/icons/CloudUpload';
import PersonIcon from '@material-ui/icons/Person';
import EditIcon from '@material-ui/icons/Edit';
import PersonOutlineIcon from '@material-ui/icons/PersonOutline';
import CheckCircleIcon from '@material-ui/icons/CheckCircle';
import RemoveCircleIcon from '@material-ui/icons/RemoveCircle';
import WarningIcon from '@material-ui/icons/Warning';
import CheckIcon from '@material-ui/icons/Check';
import AccessTimeIcon from '@material-ui/icons/AccessTime';
import DeleteForeverIcon from '@material-ui/icons/DeleteForever';

import validate from 'validate.js';
import moment from 'moment';

import constraints from '../../constraints';
import * as auth from '../../auth';

const styles = (theme) => ({
  avatar: {
    marginRight: 'auto',
    marginLeft: 'auto',

    width: theme.spacing(13.125),
    height: theme.spacing(13.125)
  },

  uploadButtonIcon: {
    marginRight: theme.spacing(1)
  }
});

const initialState = {
  profileCompletion: 0,
  securityRating: 0,

  showingField: '',

  firstName: '',
  lastName: '',
  username: '',
  emailAddress: '',

  errors: null
};

class AccountTab extends Component {
  constructor(props) {
    super(props);

    this.state = initialState;
  }

  calculateProfileCompletion = (fields) => {
    let profileCompletion = 0;

    fields.forEach((field) => {
      if (field) {
        profileCompletion += 100 / fields.length;
      }
    });

    return Math.floor(profileCompletion);
  };

  calculateSecurityRating = () => {
    return 100;
  };

  showField = (fieldId) => {
    if (!fieldId) {
      return;
    }

    this.setState({
      showingField: fieldId
    });
  };

  hideFields = () => {
    this.setState({
      showingField: '',

      firstName: '',
      lastName: '',
      username: '',
      emailAddress: '',

      errors: null
    });
  };

  changeFirstName = () => {
    const { firstName } = this.state;

    const errors = validate({
      firstName: firstName
    }, {
      firstName: constraints.firstName
    });

    if (errors) {
      this.setState({
        errors: errors
      });
    } else {
      this.setState({
        errors: null
      }, () => {
        auth.changeFirstName(firstName, () => {
          this.hideFields();
        });
      });
    }
  };

  changeLastName = () => {
    const { lastName } = this.state;

    const errors = validate({
      lastName: lastName
    }, {
      lastName: constraints.lastName
    });

    if (errors) {
      this.setState({
        errors: errors
      });
    } else {
      this.setState({
        errors: null
      }, () => {
        auth.changeLastName(lastName, () => {
          this.hideFields();
        });
      });
    }
  };

  changeUsername = () => {
    const { username } = this.state;

    const errors = validate({
      username: username
    }, {
      username: constraints.username
    });

    if (errors) {
      this.setState({
        errors: errors
      });
    } else {
      this.setState({
        errors: null
      }, () => {
        auth.changeUsername(username, () => {
          this.hideFields();
        });
      });
    }
  };

  changeEmailAddress = () => {
    const { emailAddress } = this.state;

    const errors = validate({
      emailAddress: emailAddress
    }, {
      emailAddress: constraints.emailAddress
    });

    if (errors) {
      this.setState({
        errors: errors
      });
    } else {
      this.setState({
        errors: null
      }, () => {
        auth.changeEmailAddress(emailAddress, () => {
          this.hideFields();
        });
      });
    }
  };

  changeField = (fieldId) => {
    switch (fieldId) {
      case 'firstName':
        this.changeFirstName();
        return;

      case 'lastName':
        this.changeLastName();
        return;

      case 'username':
        this.changeUsername();
        return;

      case 'emailAddress':
        this.changeEmailAddress();
        return;

      default:
        return;
    }
  };

  handleKeyDown = (event, fieldId) => {
    if (!event || !fieldId) {
      return;
    }

    if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) {
      return;
    }

    const key = event.key;

    if (!key) {
      return;
    }

    if (key === 'Escape') {
      this.hideFields();
    } else if (key === 'Enter') {
      this.changeField(fieldId);
    }
  };

  handleFirstNameChange = (event) => {
    if (!event) {
      return;
    }

    const firstName = event.target.value;

    this.setState({
      firstName: firstName
    });
  };

  handleLastNameChange = (event) => {
    if (!event) {
      return;
    }

    const lastName = event.target.value;

    this.setState({
      lastName: lastName
    });
  };

  handleUsernameChange = (event) => {
    if (!event) {
      return;
    }

    const username = event.target.value;

    this.setState({
      username: username
    });
  };

  handleEmailAddressChange = (event) => {
    if (!event) {
      return;
    }

    const emailAddress = event.target.value;

    this.setState({
      emailAddress: emailAddress
    });
  };

  render() {
    // Styling
    const { classes } = this.props;

    // Properties
    const {
      user,
      userData
    } = this.props;

    const {
      profileCompletion,
      securityRating,

      showingField,

      firstName,
      lastName,
      username,
      emailAddress,

      errors
    } = this.state;

    return (
      <DialogContent>
        <Box mb={1}>
          <Hidden xsDown>
            <Grid alignItems="center" container>
              <Grid item xs>
                <Box textAlign="center">
                  {user.photoURL &&
                    <Box mb={1}>
                      <Avatar className={classes.avatar} alt="Avatar" src={user.photoURL} />
                    </Box>
                  }

                  {!user.photoURL &&
                    <Box mb={1}>
                      <Avatar className={classes.avatar} alt="Avatar">
                        <PortraitIcon fontSize="large" />
                      </Avatar>
                    </Box>
                  }

                  <Button color="primary" variant="contained">
                    <CloudUploadIcon className={classes.uploadButtonIcon} />
                    Upload
                  </Button>
                </Box>
              </Grid>

              <Grid item xs>
                <Box textAlign="center">
                  <Typography gutterBottom variant="body1">Profile Completion</Typography>

                  {profileCompletion === 0 &&
                    <RemoveCircleIcon color="error" fontSize="large" />
                  }

                  {profileCompletion === 100 &&
                    <CheckCircleIcon color="primary" fontSize="large" />
                  }

                  {(profileCompletion !== 0 && profileCompletion !== 100)  &&
                    <CircularProgress color="secondary" size={35} thickness={5.6} value={profileCompletion} variant="static" />
                  }
                </Box>
              </Grid>

              <Grid item xs>
                <Box textAlign="center">
                  <Typography gutterBottom variant="body1">Security Rating</Typography>

                  {securityRating === 0 &&
                    <RemoveCircleIcon color="error" fontSize="large" />
                  }

                  {securityRating === 100 &&
                    <CheckCircleIcon color="primary" fontSize="large" />
                  }

                  {(securityRating !== 0 && securityRating !== 100) &&
                    <CircularProgress color="secondary" size={35} thickness={5.6} value={securityRating} variant="static" />
                  }
                </Box>
              </Grid>
            </Grid>
          </Hidden>

          <Hidden smUp>
            <Box mb={2} textAlign="center">
              {user.photoURL &&
                <Box mb={1}>
                  <Avatar className={classes.avatar} alt="Avatar" src={user.photoURL} />
                </Box>
              }

              {!user.photoURL &&
                <Box mb={1}>
                  <Avatar className={classes.avatar} alt="Avatar">
                    <PortraitIcon fontSize="large" />
                  </Avatar>
                </Box>
              }

              <Button color="primary" variant="contained">
                <CloudUploadIcon className={classes.uploadButtonIcon} />
                Upload
              </Button>
            </Box>

            <Grid container>
              <Grid item xs>
                <Box textAlign="center">
                  <Typography gutterBottom variant="body1">Profile Completion</Typography>

                  {profileCompletion === 0 &&
                    <RemoveCircleIcon color="error" fontSize="large" />
                  }

                  {profileCompletion === 100 &&
                    <CheckCircleIcon color="primary" fontSize="large" />
                  }

                  {(profileCompletion !== 0 && profileCompletion !== 100)  &&
                    <CircularProgress color="secondary" size={35} thickness={5.6} value={profileCompletion} variant="static" />
                  }
                </Box>
              </Grid>

              <Grid item xs>
                <Box textAlign="center">
                  <Typography gutterBottom variant="body1">Security Rating</Typography>

                  {securityRating === 0 &&
                    <RemoveCircleIcon color="error" fontSize="large" />
                  }

                  {securityRating === 100 &&
                    <CheckCircleIcon color="primary" fontSize="large" />
                  }

                  {(securityRating !== 0 && securityRating !== 100) &&
                    <CircularProgress color="secondary" size={35} thickness={5.6} value={securityRating} variant="static" />
                  }
                </Box>
              </Grid>
            </Grid>
          </Hidden>
        </Box>

        <List disablePadding>
          <ListItem>
            <Hidden xsDown>
              <ListItemIcon>
                <React.Fragment>
                  {userData.firstName &&
                    <PersonIcon />
                  }

                  {!userData.firstName &&
                    <Tooltip title="No first name">
                      <WarningIcon color="error" />
                    </Tooltip>
                  }
                </React.Fragment>
              </ListItemIcon>
            </Hidden>

            {showingField === 'firstName' &&
              <TextField
                autoComplete="given-name"
                autoFocus
                error={!!(errors && errors.firstName)}
                fullWidth
                helperText={(errors && errors.firstName) ? errors.firstName[0] : 'Press Enter to change your first name'}
                label="First name"
                placeholder={userData.firstName}
                required
                type="text"
                value={firstName}
                variant="filled"

                onBlur={this.hideFields}
                onKeyDown={(event) => this.handleKeyDown(event, 'firstName')}

                onChange={this.handleFirstNameChange}
              />
            }

            {showingField !== 'firstName' &&
              <React.Fragment>
                <ListItemText
                  primary="First name"
                  secondary={userData.firstName ? userData.firstName : 'You don\'t have a first name'}
                />

                <ListItemSecondaryAction>
                  {userData.firstName &&
                    <Tooltip title="Change">
                      <IconButton onClick={() => this.showField('firstName')}>
                        <EditIcon />
                      </IconButton>
                    </Tooltip>
                  }

                  {!userData.firstName &&
                    <Button
                      color="primary"
                      variant="contained"
                      onClick={() => this.showField('firstName')}>
                      Add
                    </Button>
                  }
                </ListItemSecondaryAction>
              </React.Fragment>
            }
          </ListItem>

          <ListItem>
            <Hidden xsDown>
              <ListItemIcon>
                <React.Fragment>
                  {userData.lastName &&
                    <PersonIcon />
                  }

                  {!userData.lastName &&
                    <Tooltip title="No last name">
                      <WarningIcon color="error" />
                    </Tooltip>
                  }
                </React.Fragment>
              </ListItemIcon>
            </Hidden>

            {showingField === 'lastName' &&
              <TextField
                autoComplete="family-name"
                autoFocus
                error={!!(errors && errors.lastName)}
                fullWidth
                helperText={(errors && errors.lastName) ? errors.lastName[0] : 'Press Enter to change your last name'}
                label="Last name"
                placeholder={userData.lastName}
                required
                type="text"
                value={lastName}
                variant="filled"

                onBlur={this.hideFields}
                onKeyDown={(event) => this.handleKeyDown(event, 'lastName')}

                onChange={this.handleLastNameChange}
              />
            }

            {showingField !== 'lastName' &&
              <React.Fragment>
                <ListItemText
                  primary="Last name"
                  secondary={userData.lastName ? userData.lastName : 'You don\'t have a last name'}
                />

                <ListItemSecondaryAction>
                  {userData.lastName &&
                    <Tooltip title="Change">
                      <IconButton onClick={() => this.showField('lastName')}>
                        <EditIcon />
                      </IconButton>
                    </Tooltip>
                  }

                  {!userData.lastName &&
                    <Button
                      color="primary"
                      variant="contained"
                      onClick={() => this.showField('lastName')}>
                      Add
                    </Button>
                  }
                </ListItemSecondaryAction>
              </React.Fragment>
            }
          </ListItem>

          <ListItem>
            <Hidden xsDown>
              <ListItemIcon>
                <React.Fragment>
                  {userData.username &&
                    <PersonOutlineIcon />
                  }

                  {!userData.username &&
                    <Tooltip title="No username">
                      <WarningIcon color="error" />
                    </Tooltip>
                  }
                </React.Fragment>
              </ListItemIcon>
            </Hidden>

            {showingField === 'username' &&
              <TextField
                autoComplete="username"
                autoFocus
                error={!!(errors && errors.username)}
                fullWidth
                helperText={(errors && errors.username) ? errors.username[0] : 'Press Enter to change your username'}
                label="Username"
                placeholder={userData.username}
                required
                type="text"
                value={username}
                variant="filled"

                onBlur={this.hideFields}
                onKeyDown={(event) => this.handleKeyDown(event, 'username')}

                onChange={this.handleUsernameChange}
              />
            }

            {showingField !== 'username' &&
              <React.Fragment>
                <ListItemText
                  primary="Username"
                  secondary={userData.username ? userData.username : 'You don\'t have a username'}
                />

                <ListItemSecondaryAction>
                  {userData.username &&
                    <Tooltip title="Change">
                      <IconButton onClick={() => this.showField('username')}>
                        <EditIcon />
                      </IconButton>
                    </Tooltip>
                  }

                  {!userData.username &&
                    <Button
                      color="primary"
                      variant="contained"
                      onClick={() => this.showField('username')}>
                      Add
                    </Button>
                  }
                </ListItemSecondaryAction>
              </React.Fragment>
            }
          </ListItem>

          <ListItem>
            {user.email &&
              <ListItemIcon>
                <React.Fragment>
                  {user.emailVerified &&
                    <Tooltip title="Verified">
                      <CheckCircleIcon color="primary" />
                    </Tooltip>
                  }

                  {!user.emailVerified &&
                    <Tooltip title="Not verified">
                      <WarningIcon color="error" />
                    </Tooltip>
                  }
                </React.Fragment>
              </ListItemIcon>
            }

            {!user.email &&
              <Hidden xsDown>
                <ListItemIcon>
                  <Tooltip title="No e-mail address">
                    <WarningIcon color="error" />
                  </Tooltip>
                </ListItemIcon>
              </Hidden>
            }

            {showingField === 'emailAddress' &&
              <TextField
                autoComplete="email"
                autoFocus
                error={!!(errors && errors.emailAddress)}
                fullWidth
                helperText={(errors && errors.emailAddress) ? errors.emailAddress[0] : 'Press Enter to change your e-mail address'}
                label="E-mail address"
                placeholder={user.email}
                required
                type="email"
                value={emailAddress}
                variant="filled"

                onBlur={this.hideFields}
                onKeyDown={(event) => this.handleKeyDown(event, 'emailAddress')}

                onChange={this.handleEmailAddressChange}
              />
            }

            {showingField !== 'emailAddress' &&
              <React.Fragment>
                <ListItemText
                  primary="E-mail address"
                  secondary={user.email ? user.email : 'You don\'t have an e-mail address'}
                />

                {(user.email && !user.emailVerified) &&
                  <Box clone mr={7}>
                    <ListItemSecondaryAction>
                      <Tooltip title="Verify">
                        <IconButton color="secondary">
                          <CheckIcon />
                        </IconButton>
                      </Tooltip>
                    </ListItemSecondaryAction>
                  </Box>
                }

                <ListItemSecondaryAction>
                  {user.email &&
                    <Tooltip title="Change">
                      <IconButton onClick={() => this.showField('emailAddress')}>
                        <EditIcon />
                      </IconButton>
                    </Tooltip>
                  }

                  {!user.email &&
                    <Button
                      color="primary"
                      variant="contained"
                      onClick={() => this.showField('emailAddress')}>
                      Add
                    </Button>
                  }
                </ListItemSecondaryAction>
              </React.Fragment>
            }
          </ListItem>

          <ListItem>
            <Hidden xsDown>
              <ListItemIcon>
                <AccessTimeIcon />
              </ListItemIcon>
            </Hidden>

            <ListItemText
              primary="Signed in"
              secondary={moment(user.metadata.lastSignInTime).format('LLLL')}
            />
          </ListItem>

          <ListItem>
            <Hidden xsDown>
              <ListItemIcon>
                <AccessTimeIcon />
              </ListItemIcon>
            </Hidden>

            <ListItemText
              primary="Signed up"
              secondary={moment(user.metadata.creationTime).format('LL')}
            />
          </ListItem>

          <ListItem>
            <Hidden xsDown>
              <ListItemIcon>
                <DeleteForeverIcon />
              </ListItemIcon>
            </Hidden>

            <ListItemText
              primary="Delete account"
              secondary="Accounts cannot be recovered"
            />

            <ListItemSecondaryAction>
              <Button color="secondary" variant="contained">Delete</Button>
            </ListItemSecondaryAction>
          </ListItem>
        </List>
      </DialogContent>
    );
  }

  componentDidMount() {
    const { user, userData } = this.props;

    const profileCompletion = this.calculateProfileCompletion([
      user.photoURL,
      userData.firstName,
      userData.lastName,
      userData.username,
      user.email,
      user.email && user.emailVerified
    ]);

    const securityRating = this.calculateSecurityRating();

    this.setState({
      profileCompletion: profileCompletion,
      securityRating: securityRating
    });
  }
}

AccountTab.propTypes = {
  // Styling
  classes: PropTypes.object.isRequired,

  // Properties
  user: PropTypes.object.isRequired,
  userData: PropTypes.object.isRequired
};

export default withStyles(styles)(AccountTab);