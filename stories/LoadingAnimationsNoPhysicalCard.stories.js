import { renderElmApp } from './elmHarness';
import { serverData } from './serverData';

export default {
    title: 'Loading Animations/No Physical Card',
    render: (args) => renderElmApp({
        serverData: args.serverData,
        localData: JSON.stringify(args.localData),
        storybookState: args.storybookState,
    }),
    args: {
        serverData,
        localData: { orderPhysicalCard: false },
    },
};

export const WaitingForSingleSignOn = {
    args: {
        storybookState: { formState: "creatingRampAccount" },
    },
};

export const WaitingForRampAccount = {
    args: {
        storybookState: { formState: { kind: "creatingRampAccount", requestCompleted: true } }
    },
};

export const RedirectingToRamp = {
    args: {
        storybookState: { formState: "rampAccountCreated" }
    },
};