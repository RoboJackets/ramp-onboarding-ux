import { Elm } from '../elm/StorybookHarness.elm';

// The Elm debugger build requires the mount node to be attached to the DOM
// before init, so boot is deferred until Storybook inserts the container.
export const renderElmApp = (flags) => {
  const container = document.createElement('div');
  const boot = (remaining) => {
    if (container.isConnected) {
      Elm.StorybookHarness.init({
        node: container,
        flags,
      });
      return;
    }
    if (remaining > 0) {
      requestAnimationFrame(() => boot(remaining - 1));
    }
  };
  requestAnimationFrame(() => boot(300));
  return container;
};
