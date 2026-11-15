import { renderElmApp } from './elmHarness';
import { serverData } from './serverData';

export default {
    title: 'Loading Animations/With Physical Card',
    render: (args) => renderElmApp({
        serverData: args.serverData,
        localData: JSON.stringify(args.localData),
        storybookState: args.storybookState,
    }),
    args: {
        serverData,
        localData: { orderPhysicalCard: true },
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

export const WaitingForPhysicalCard = {
    args: {
        storybookState: { formState: "rampAccountCreated" }
    },
};

export const RedirectingToRamp = {
    args: {
        storybookState: { formState: "physicalCardOrdered" }
    },
};

