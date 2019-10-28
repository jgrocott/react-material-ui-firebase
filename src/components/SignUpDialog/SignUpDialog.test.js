import React from 'react';

import ReactDOM from 'react-dom';

import SignUpDialog from './SignUpDialog';

it('renders without crashing', () => {
  const div = document.createElement('div');

  ReactDOM.render(
    <SignUpDialog
      dialogProps={{
        open: true,

        onClose: () => {},
      }}
      signUp={() => {}}
      onAuthProviderClick={() => {}}
      openSnackbar={() => {}}
    />,
    div
  );

  ReactDOM.unmountComponentAtNode(div);
});
