/** @type { import('@storybook/html-vite').Preview } */
const preview = {
  parameters: {
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
    options: {
      storySort: {
        order: [
          "Onboarding Form",
          "Loading Animations",
          "Errors",
        ],
      },
    },
  },
};

export default preview;