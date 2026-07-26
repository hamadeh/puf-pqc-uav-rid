function upgrade_RO_PUF_challenge_schedule()
% Add the fixed data-independent balanced orientation to the older
% five-column RO-PUF challenge_schedule.csv.
%
% Input:
%   challenge_schedule.csv
%
% Output:
%   challenge_schedule_balanced.csv

clc;

input_file  = 'challenge_schedule.csv';
output_file = 'challenge_schedule_balanced.csv';

bank_size = 64;
n_ro = 128;
expected_challenges = 1023;

if ~isfile(input_file)
    error('Input file not found: %s', input_file);
end

%% Read the older schedule

try
    T = readtable(input_file, ...
        'VariableNamingRule', 'preserve');
catch
    T = readtable(input_file, ...
        'PreserveVariableNames', true);
end

if height(T) ~= expected_challenges
    error('Expected %d challenges, but found %d.', ...
        expected_challenges, height(T));
end

names = T.Properties.VariableNames;
names_normalized = cell(size(names));

for k = 1:numel(names)
    names_normalized{k} = lower( ...
        regexprep(char(names{k}), '[^a-zA-Z0-9]', ''));
end

%% Locate required columns

idx_challenge = find_alias(names_normalized, ...
    {'challengeindex','challenge','bitindex','responseindex'});

idx_global_a = find_alias(names_normalized, ...
    {'globalroaindex','globalroa','roaglobalindex','globalindexa'});

idx_global_b = find_alias(names_normalized, ...
    {'globalrobindex','globalrob','robglobalindex','globalindexb'});

idx_local_a = find_alias(names_normalized, ...
    {'bankaindex','bankaroindex','roaindex','roa','banka'});

idx_local_b = find_alias(names_normalized, ...
    {'bankbindex','bankbroindex','robindex','rob','bankb'});

%% Extract Bank-A and Bank-B global zero-based indices

if ~isempty(idx_global_a) && ~isempty(idx_global_b)

    global_a = double(T{:,idx_global_a});
    global_b = double(T{:,idx_global_b});

    % Expected zero-based convention:
    % Bank A = 0...63
    % Bank B = 64...127
    if all(global_a >= 0 & global_a < bank_size) && ...
            all(global_b >= bank_size & global_b < n_ro)

        % Already zero-based.

    elseif all(global_a >= 1 & global_a <= bank_size) && ...
            all(global_b >= bank_size+1 & global_b <= n_ro)

        warning('One-based global indices found; converting to zero-based.');

        global_a = global_a - 1;
        global_b = global_b - 1;

    else
        error(['Global oscillator indices do not match Bank A=0...63 ' ...
               'and Bank B=64...127.']);
    end

elseif ~isempty(idx_local_a) && ~isempty(idx_local_b)

    local_a = normalize_bank_indices( ...
        double(T{:,idx_local_a}), bank_size, 'Bank A');

    local_b = normalize_bank_indices( ...
        double(T{:,idx_local_b}), bank_size, 'Bank B');

    global_a = local_a;
    global_b = bank_size + local_b;

else
    error(['The CSV must contain either global_RO_A_index and ' ...
           'global_RO_B_index, or bank_A_index and bank_B_index.']);
end

global_a = global_a(:);
global_b = global_b(:);

%% Recover the local pair graph

local_a_one_based = global_a + 1;
local_b_one_based = global_b - bank_size + 1;

challenge_pairs = [ ...
    local_a_one_based, ...
    local_b_one_based];

if size(unique(challenge_pairs, 'rows'),1) ~= expected_challenges
    error('The challenge schedule contains duplicate oscillator pairs.');
end

%% Generate the exact fixed Euler-balanced orientation

orientation = generate_euler_balanced_orientation( ...
    challenge_pairs, bank_size);

plus_count = sum(orientation == 1);
minus_count = sum(orientation == -1);

if ~isequal(sort([plus_count minus_count]), [511 512])
    error('Expected a 511/512 orientation split; obtained %d/%d.', ...
        plus_count, minus_count);
end

%% Form the oriented first and second oscillator indices

first_global = global_a;
second_global = global_b;

reverse_mask = orientation == -1;

first_global(reverse_mask) = global_b(reverse_mask);
second_global(reverse_mask) = global_a(reverse_mask);

%% Challenge index

if isempty(idx_challenge)
    challenge_index = (0:expected_challenges-1)';
else
    challenge_index = double(T{:,idx_challenge});

    if all(challenge_index >= 1) && ...
            max(challenge_index) == expected_challenges && ...
            ~any(challenge_index == 0)

        challenge_index = challenge_index - 1;
    end
end

%% Derive local zero-based bank indices

bank_a_index = global_a;
bank_b_index = global_b - bank_size;

%% Validate use and orientation balance per oscillator

total_usage = accumarray( ...
    [global_a+1; global_b+1], 1, [n_ro 1]);

forward_usage = accumarray( ...
    [global_a+1; global_b+1], ...
    [orientation == 1; orientation == 1], ...
    [n_ro 1]);

reverse_usage = total_usage - forward_usage;

orientation_imbalance = ...
    abs(forward_usage-reverse_usage);

if min(total_usage) < 15 || max(total_usage) > 16
    error('Per-RO challenge usage is outside the expected 15-16 range.');
end

if max(orientation_imbalance) > 1
    error('Per-RO orientation imbalance exceeds one comparison.');
end

%% Export the final eight-column schedule

balanced_schedule = table( ...
    challenge_index(:), ...
    bank_a_index(:), ...
    bank_b_index(:), ...
    global_a(:), ...
    global_b(:), ...
    orientation(:), ...
    first_global(:), ...
    second_global(:), ...
    'VariableNames', { ...
    'challenge_index', ...
    'bank_A_index', ...
    'bank_B_index', ...
    'global_RO_A_index', ...
    'global_RO_B_index', ...
    'orientation_code', ...
    'first_global_RO_index', ...
    'second_global_RO_index'});

writetable(balanced_schedule, output_file);

%% Print verification

fprintf('\n=========== BALANCED CHALLENGE SCHEDULE CREATED ===========\n');
fprintf('Input file                         : %s\n', input_file);
fprintf('Output file                        : %s\n', output_file);
fprintf('Challenge positions                : %d\n', height(balanced_schedule));
fprintf('Orientation +1 / -1                : %d / %d\n', ...
    plus_count, minus_count);
fprintf('Per-RO total usage range           : %d to %d\n', ...
    min(total_usage), max(total_usage));
fprintf('Maximum per-RO orientation imbalance: %d\n', ...
    max(orientation_imbalance));
fprintf('============================================================\n');

disp(balanced_schedule(1:10,:));

end

%% ========================================================================
function idx = find_alias(names_normalized, aliases)

idx = [];

for k = 1:numel(aliases)

    candidate = find( ...
        strcmp(names_normalized, aliases{k}), 1);

    if ~isempty(candidate)
        idx = candidate;
        return;
    end
end

end

%% ========================================================================
function zero_based = normalize_bank_indices(values, bank_size, label)

values = values(:);

if all(values >= 0 & values < bank_size)

    zero_based = values;

elseif all(values >= 1 & values <= bank_size) && ...
        any(values == bank_size) && ...
        ~any(values == 0)

    warning('One-based %s indices found; converting to zero-based.', ...
        label);

    zero_based = values - 1;

else
    error('%s indices do not fit 0...%d or 1...%d.', ...
        label, bank_size-1, bank_size);
end

end

%% ========================================================================
function orientation = ...
    generate_euler_balanced_orientation(challenge, bank_size)
% Alternately color the edges of an Euler circuit.
%
% For this 1023-comparison graph, adding one dummy edge produces
% a 1024-edge Euler circuit. Alternating +1 and -1 along the circuit
% gives 512 versus 511 orientations and per-oscillator imbalance <= 1.

n_vertices = 2*bank_size;

edges = [ ...
    challenge(:,1), ...
    bank_size + challenge(:,2)];

degree = accumarray( ...
    edges(:), 1, [n_vertices 1]);

odd_vertices = find(mod(degree,2) == 1);

if numel(odd_vertices) ~= 2
    error(['Expected exactly two odd-degree vertices, but found %d. ' ...
           'Confirm that this is the original 1023-pair schedule.'], ...
           numel(odd_vertices));
end

original_edge_count = size(edges,1);

edges(end+1,:) = odd_vertices(:)';
dummy_edge = size(edges,1);

adjacency = cell(n_vertices,1);

for edge_id = 1:size(edges,1)

    u = edges(edge_id,1);
    v = edges(edge_id,2);

    adjacency{u}(end+1) = edge_id; %#ok<AGROW>
    adjacency{v}(end+1) = edge_id; %#ok<AGROW>
end

used = false(size(edges,1),1);
next_position = ones(n_vertices,1);

vertex_stack = edges(1,1);
edge_stack = zeros(0,1);

reverse_circuit_edges = zeros(size(edges,1),1);
circuit_count = 0;

while ~isempty(vertex_stack)

    vertex = vertex_stack(end);

    while next_position(vertex) <= ...
            numel(adjacency{vertex}) && ...
            used(adjacency{vertex}(next_position(vertex)))

        next_position(vertex) = ...
            next_position(vertex)+1;
    end

    if next_position(vertex) <= numel(adjacency{vertex})

        edge_id = ...
            adjacency{vertex}(next_position(vertex));

        next_position(vertex) = ...
            next_position(vertex)+1;

        if used(edge_id)
            continue;
        end

        used(edge_id) = true;

        if edges(edge_id,1) == vertex
            next_vertex = edges(edge_id,2);
        else
            next_vertex = edges(edge_id,1);
        end

        vertex_stack(end+1) = next_vertex; %#ok<AGROW>
        edge_stack(end+1) = edge_id; %#ok<AGROW>

    else
        vertex_stack(end) = [];

        if ~isempty(edge_stack)

            circuit_count = circuit_count+1;

            reverse_circuit_edges(circuit_count) = ...
                edge_stack(end);

            edge_stack(end) = [];
        end
    end
end

if ~all(used)
    error('Challenge graph is disconnected.');
end

circuit_edges = ...
    flipud(reverse_circuit_edges(1:circuit_count));

if numel(circuit_edges) ~= size(edges,1)
    error('Euler circuit did not contain every edge exactly once.');
end

edge_color = zeros(size(edges,1),1);

edge_color(circuit_edges(1:2:end)) = 1;
edge_color(circuit_edges(2:2:end)) = -1;

orientation = edge_color(1:original_edge_count);

if edge_color(dummy_edge) == 0
    error('The dummy edge was not included in the Euler circuit.');
end

end